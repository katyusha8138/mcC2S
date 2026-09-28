// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 mcC2S contributors

package io.github.katyusha8138.mcc2s.neoforge.server;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.context.CommandContext;
import io.github.katyusha8138.mcc2s.common.AdminActions;
import io.github.katyusha8138.mcc2s.common.EntryKindNames;
import io.github.katyusha8138.mcc2s.common.ServerRuntime;
import java.time.Clock;
import java.util.function.Function;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.commands.SharedSuggestionProvider;
import net.minecraft.network.chat.Component;
import net.neoforged.neoforge.event.RegisterCommandsEvent;

/**
 * `/mcc2s` 管理コマンド(OP 権限レベル 3 以上、またはサーバーコンソール)。中身は common の {@link AdminActions}。
 * <pre>
 * /mcc2s status
 * /mcc2s reload
 * /mcc2s whitelist add &lt;player&gt;                       そのプレイヤーの直近の違反を許可リストに追加
 * /mcc2s whitelist addhash &lt;kind&gt; &lt;sha256&gt; [id]      ハッシュを直接許可
 * </pre>
 */
public final class ServerCommands {
    private ServerCommands() {}

    public static void register(RegisterCommandsEvent event) {
        CommandDispatcher<CommandSourceStack> d = event.getDispatcher();
        d.register(Commands.literal("mcc2s")
                .requires(src -> src.hasPermission(3))
                .then(Commands.literal("status").executes(c -> run(c, rt -> AdminActions.status(rt))))
                .then(Commands.literal("reload").executes(c -> run(c, rt -> AdminActions.reload(rt))))
                .then(Commands.literal("whitelist")
                        .then(Commands.literal("add")
                                .then(Commands.argument("player", StringArgumentType.word())
                                        .executes(c -> {
                                            String player = StringArgumentType.getString(c, "player");
                                            String who = c.getSource().getTextName();
                                            return run(c, rt -> AdminActions.whitelistAdd(rt, player, who, Clock.systemUTC()));
                                        })))
                        .then(Commands.literal("addhash")
                                .then(Commands.argument("kind", StringArgumentType.word())
                                        .suggests((c, b) -> SharedSuggestionProvider.suggest(EntryKindNames.NAMES, b))
                                        .then(Commands.argument("sha256", StringArgumentType.word())
                                                .executes(c -> addHash(c, null))
                                                .then(Commands.argument("id", StringArgumentType.greedyString())
                                                        .executes(c -> addHash(c, StringArgumentType.getString(c, "id")))))))));
    }

    private static int addHash(CommandContext<CommandSourceStack> c, String id) {
        String kind = StringArgumentType.getString(c, "kind");
        String sha = StringArgumentType.getString(c, "sha256");
        String who = c.getSource().getTextName();
        return run(c, rt -> AdminActions.whitelistAddHash(rt, kind, sha, id, who, Clock.systemUTC()));
    }

    private static int run(CommandContext<CommandSourceStack> c, Function<ServerRuntime, AdminActions.Response> action) {
        ServerRuntime rt = ServerHooks.runtime();
        CommandSourceStack src = c.getSource();
        if (rt == null) {
            src.sendFailure(Component.literal("mcC2S is not running"));
            return 0;
        }
        AdminActions.Response r = action.apply(rt);
        for (String line : r.lines()) {
            Component msg = Component.literal("[mcC2S] " + line);
            if (r.ok()) {
                src.sendSuccess(() -> msg, false);
            } else {
                src.sendFailure(msg);
            }
        }
        return r.ok() ? 1 : 0;
    }
}
