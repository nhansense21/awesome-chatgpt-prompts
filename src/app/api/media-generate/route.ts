import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { auth } from "@/lib/auth";
import { db } from "@/lib/db";
import { isPrivateUrl } from "@/lib/webhook";
import {
  getMediaGeneratorPlugin,
  getAvailableModels,
  isMediaGenerationAvailable,
} from "@/lib/plugins/media-generators";

export async function GET() {
  const session = await auth();

  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const available = isMediaGenerationAvailable();
  const imageModels = getAvailableModels("image");
  const videoModels = getAvailableModels("video");
  const audioModels = getAvailableModels("audio");

  // Get user's credit info
  const user = await db.user.findUnique({
    where: { id: session.user.id },
    select: {
      generationCreditsRemaining: true,
      dailyGenerationLimit: true,
      flagged: true,
    },
  });

  return NextResponse.json({
    available,
    imageModels,
    videoModels,
    audioModels,
    credits: {
      remaining: user?.generationCreditsRemaining ?? 0,
      daily: user?.dailyGenerationLimit ?? 0,
    },
    canGenerate: !user?.flagged && (user?.generationCreditsRemaining ?? 0) > 0,
  });
}

export async function POST(request: NextRequest) {
  const session = await auth();

  if (!session?.user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    // Check user's credits and flagged status
    const user = await db.user.findUnique({
      where: { id: session.user.id },
      select: {
        generationCreditsRemaining: true,
        flagged: true,
      },
    });

    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    // Block flagged users
    if (user.flagged) {
      return NextResponse.json(
        { error: "Your account has been flagged. Media generation is disabled." },
        { status: 403 }
      );
    }

    // Check credits
    if (user.generationCreditsRemaining <= 0) {
      return NextResponse.json(
        { error: "No generation credits remaining. Credits reset daily." },
        { status: 403 }
      );
    }

    const body = await request.json();

    const generationSchema = z.object({
      prompt: z.string().min(1, "Prompt is required").max(2000),
      model: z.string().min(1).max(100).regex(/^[a-zA-Z0-9._\-/]+$/, "Invalid model identifier"),
      provider: z.string().min(1).max(50).regex(/^[a-zA-Z0-9_-]+$/, "Invalid provider identifier"),
      type: z.enum(["image", "video", "audio"]),
      inputImageUrl: z.string().url().optional(),
      resolution: z.string().regex(/^\d+x\d+$/).optional(),
      aspectRatio: z.string().regex(/^\d+:\d+$/).optional(),
    });

    const parsed = generationSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        { error: "Invalid input", details: parsed.error.flatten().fieldErrors },
        { status: 400 }
      );
    }

    const { prompt, model, provider, type, inputImageUrl, resolution, aspectRatio } = parsed.data;

    // Block SSRF: reject inputImageUrl pointing at private/internal networks
    if (inputImageUrl && isPrivateUrl(inputImageUrl)) {
      return NextResponse.json(
        { error: "Invalid inputImageUrl" },
        { status: 400 }
      );
    }

    const plugin = getMediaGeneratorPlugin(provider);

    if (!plugin) {
      return NextResponse.json(
        { error: `Provider "${provider}" not found` },
        { status: 404 }
      );
    }

    if (!plugin.isEnabled()) {
      return NextResponse.json(
        { error: `Provider "${provider}" is not enabled` },
        { status: 400 }
      );
    }

    const task = await plugin.startGeneration({
      prompt,
      model,
      type,
      inputImageUrl,
      resolution,
      aspectRatio,
    });

    // Deduct one credit after successful generation start
    await db.user.update({
      where: { id: session.user.id },
      data: {
        generationCreditsRemaining: {
          decrement: 1,
        },
      },
    });

    return NextResponse.json({
      success: true,
      taskId: task.taskId,
      socketAccessToken: task.socketAccessToken,
      webSocketUrl: plugin.getWebSocketUrl(),
      provider,
    });
  } catch (error) {
    console.error("Media generation error:", error);
    return NextResponse.json(
      { error: "Generation failed" },
      { status: 500 }
    );
  }
}
