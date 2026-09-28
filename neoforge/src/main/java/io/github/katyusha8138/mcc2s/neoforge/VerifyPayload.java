// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.neoforge;

import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.ResourceLocation;

/**
 * 検証メッセージ(チャレンジ / 添付 / 判定)の 1 チャンク。中身は core の {@code Fragmenter.Chunk} のバイト列。
 * サーバー行きのカスタムペイロードは約 32KB が上限なので、チャンク本体は 28,000 バイト以下に収めている。
 */
public record VerifyPayload(byte[] data) implements CustomPacketPayload {
    public static final Type<VerifyPayload> TYPE =
            new Type<>(ResourceLocation.fromNamespaceAndPath(McC2S.MOD_ID, "verify"));

    /** ヘッダ込みで上限(32,767)を超えない範囲。 */
    private static final int MAX_BYTES = 30_000;

    public static final StreamCodec<FriendlyByteBuf, VerifyPayload> CODEC = CustomPacketPayload.codec(
            (payload, buf) -> buf.writeByteArray(payload.data),
            buf -> new VerifyPayload(buf.readByteArray(MAX_BYTES)));

    @Override
    public Type<? extends CustomPacketPayload> type() {
        return TYPE;
    }
}
