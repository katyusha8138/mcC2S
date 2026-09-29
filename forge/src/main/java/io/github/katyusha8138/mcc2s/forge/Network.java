// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.forge;

import io.github.katyusha8138.mcc2s.forge.client.ClientHooks;
import io.github.katyusha8138.mcc2s.forge.server.ServerHooks;
import io.netty.buffer.Unpooled;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import net.minecraft.network.Connection;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.protocol.Packet;
import net.minecraft.resources.ResourceLocation;
import net.minecraftforge.network.LoginWrapper;
import net.minecraftforge.network.NetworkDirection;
import net.minecraftforge.network.NetworkEvent;
import net.minecraftforge.network.NetworkRegistry;
import net.minecraftforge.network.simple.SimpleChannel;
import org.apache.commons.lang3.tuple.Pair;

/**
 * 検証メッセージ(チャレンジ / 添付 / 判定)を運ぶチャンネル。メッセージは 1 種類で、中身は core の
 * {@code Fragmenter.Chunk} のバイト列。ログイン中(ワールド参加前)とプレイ中(再検証)の両方で同じメッセージを使う。
 *
 * <p>Forge 1.20.1 には NeoForge のような「設定フェーズ」が無いため、ログイン交渉(FML ハンドシェイク)の中で検証する。
 * ログイン交渉はサーバー側の {@code PlayerNegotiationEvent} に Future を登録すると、その完了まで先へ進まない。
 *
 * <p>チャンネルは「導入していない相手を許可する」版で登録する(mcC2S 未導入サーバーにも導入クライアントが参加できる)。
 * mcC2S 導入サーバーへの未導入クライアントは Forge ではなく mcC2S 自身が、日英併記の案内付きで拒否する。
 */
public final class Network {
    // ResourceLocation(String, String) は 47.4.x で削除予定の扱いだが、fromNamespaceAndPath は古い 47.x には無い。
    @SuppressWarnings("removal")
    public static final ResourceLocation CHANNEL_ID = new ResourceLocation(McC2S.MOD_ID, "verify");

    private static final String PROTOCOL = "1";
    /** チャンク(本体 28,000 バイト以下)にヘッダを足しても、サーバー行きの上限(32,767)を超えない範囲。 */
    private static final int MAX_BYTES = 30_000;
    /** FML 自身のログイン照会(0, 1, 2, ...)と番号が重ならないようにする。 */
    private static final AtomicInteger QUERY_ID = new AtomicInteger(0x4D430000);

    public static final SimpleChannel CHANNEL = NetworkRegistry.newSimpleChannel(
            CHANNEL_ID, () -> PROTOCOL, NetworkRegistry.acceptMissingOr(PROTOCOL), NetworkRegistry.acceptMissingOr(PROTOCOL));

    /** 検証メッセージの 1 チャンク。 */
    public record VerifyMessage(byte[] data) {}

    private Network() {}

    public static void register() {
        CHANNEL.registerMessage(0, VerifyMessage.class, Network::encode, Network::decode, Network::handle);
    }

    private static void encode(VerifyMessage message, FriendlyByteBuf buf) {
        buf.writeByteArray(message.data());
    }

    private static VerifyMessage decode(FriendlyByteBuf buf) {
        return new VerifyMessage(buf.readByteArray(MAX_BYTES));
    }

    private static void handle(VerifyMessage message, Supplier<NetworkEvent.Context> supplier) {
        NetworkEvent.Context context = supplier.get();
        // ネットワークスレッドで処理する(ハッシュ計算などでゲームを止めないため)
        context.setPacketHandled(true);
        switch (context.getDirection()) {
            case LOGIN_TO_SERVER, PLAY_TO_SERVER -> ServerHooks.handle(message.data(), context);
            case LOGIN_TO_CLIENT, PLAY_TO_CLIENT -> ClientHooks.handle(message.data(), context);
        }
    }

    /**
     * ログイン中のクライアントへ、こちらから先に照会(チャレンジ)を送る。
     * FML のログイン照会は「一覧を最初に集めて 1 tick に 1 つ送る」固定の仕組みで、ログイン名に結び付いた
     * チャレンジ(接続ごとに生成)を後から差し込めない。そのため、FML が内部で行っているのと同じ包み方
     * ({@code fml:loginwrapper})で自前のパケットを送る。返信はクライアントが同じ包み方で返す。
     */
    public static void sendLoginQuery(Connection connection, byte[] chunk) {
        FriendlyByteBuf inner = new FriendlyByteBuf(Unpooled.buffer());
        CHANNEL.encodeMessage(new VerifyMessage(chunk), inner);
        FriendlyByteBuf wrapped = new FriendlyByteBuf(Unpooled.buffer(inner.readableBytes() + 32));
        wrapped.writeResourceLocation(CHANNEL_ID);
        wrapped.writeVarInt(inner.readableBytes());
        wrapped.writeBytes(inner);
        Packet<?> packet = NetworkDirection.LOGIN_TO_CLIENT
                .buildPacket(Pair.of(wrapped, QUERY_ID.incrementAndGet()), LoginWrapper.WRAPPER)
                .getThis();
        connection.send(packet);
    }
}
