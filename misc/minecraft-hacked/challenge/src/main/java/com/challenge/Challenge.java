package com.challenge;

import carpet.CarpetExtension;
import carpet.CarpetServer;
import carpet.api.settings.SettingsManager;
import carpet.fakes.ServerPlayerEntityInterface;
import carpet.helpers.EntityPlayerActionPack;
import carpet.utils.Messenger;
import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import com.mojang.brigadier.context.CommandContext;
import com.mojang.brigadier.exceptions.CommandSyntaxException;
import net.fabricmc.api.ModInitializer;

import net.minecraft.block.BlockState;
import net.minecraft.block.pattern.CachedBlockPosition;
import net.minecraft.command.CommandRegistryAccess;
import net.minecraft.command.argument.BlockPosArgumentType;
import net.minecraft.command.argument.Vec3ArgumentType;
import net.minecraft.entity.EntityType;
import net.minecraft.entity.projectile.ArrowEntity;
import net.minecraft.item.ItemStack;
import net.minecraft.item.Items;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.command.ServerCommandSource;
import net.minecraft.server.network.ServerPlayerEntity;
import net.minecraft.server.world.ServerWorld;
import net.minecraft.util.math.*;
import net.minecraft.world.GameMode;
import net.minecraft.world.GameRules;
import net.minecraft.world.TeleportTarget;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.util.List;

import static net.minecraft.server.command.CommandManager.argument;
import static net.minecraft.server.command.CommandManager.literal;

public class Challenge implements CarpetExtension, ModInitializer {
	// This logger is used to write text to the console and the log file.
	// It is considered best practice to use your mod id as the logger's name.
	// That way, it's clear which mod wrote info, warnings, and errors.
    public static final Logger LOGGER = LoggerFactory.getLogger("Challenge");
	private static SettingsManager mySettingManager;
	private int bowInUse = 0;
	private boolean hasBow = false;
	private ServerPlayerEntity chalCaller;
	static {
		mySettingManager = new SettingsManager("1.0", "Challenge", "Challenge Mod");
		CarpetServer.manageExtension(new Challenge());
	}

	@Override
	public void onInitialize() {
	}

	@Override
	public void onGameStarted() {

	}

	@Override
	public void onServerLoaded(MinecraftServer server) {
	}

	@Override
	public void onTick(MinecraftServer server) {
		if(bowInUse > 0){
			ServerPlayerEntity ctfplayer = server.getPlayerManager().getPlayer("LiveOverflow");
			assert ctfplayer != null;
			if(bowInUse == 1){
				List<ArrowEntity> entities = ctfplayer.getWorld().getEntitiesByType(EntityType.ARROW, new Box(ctfplayer.getBlockPos()).expand(10), e -> e.getOwner().equals(ctfplayer));
				for(ArrowEntity entity: entities){
					entity.teleport(chalCaller.getX(), chalCaller.getY(), chalCaller.getZ());
				}
			}else if(bowInUse == 2){
				((ServerPlayerEntityInterface)ctfplayer).getActionPack().stopAll();
			}
			bowInUse -= 1;
		}
	}

	public static BlockPos convert(Vec3d vec3d) {
		Vec3i vec = new Vec3i((int)Math.floor(vec3d.x), (int)Math.floor(vec3d.y), (int)Math.floor(vec3d.z));
		return new BlockPos(vec);
	}

	private int executeClone(CommandContext<ServerCommandSource> ctx) throws CommandSyntaxException {
		ServerWorld world = ctx.getSource().getWorld();
		BlockPos src1 = BlockPosArgumentType.getBlockPos(ctx, "src1");
		BlockPos src2 = BlockPosArgumentType.getBlockPos(ctx, "src2");
		BlockPos dst = BlockPosArgumentType.getBlockPos(ctx, "dst");
		BlockBox blockBox = BlockBox.create(src1, src2);
		BlockBox blockBox2 = BlockBox.create(dst, dst.add(blockBox.getDimensions()));
		if (blockBox.intersects(blockBox2)) {
			Messenger.m(ctx.getSource(), "r Boxes intersect");
			return 0;
		}

		int sz = blockBox.getBlockCountX() * blockBox.getBlockCountY() * blockBox.getBlockCountZ();
		if (sz > 32768) {
			Messenger.m(ctx.getSource(), "r Clone volume is too large");
			return 0;
		}

		BlockPos offset = new BlockPos(
				blockBox2.getMinX() - blockBox.getMinX(),
				blockBox2.getMinY() - blockBox.getMinY(),
				blockBox2.getMinZ() - blockBox.getMinZ()
		);
		for (int i = blockBox.getMinZ(); i <= blockBox.getMaxZ(); i++) {
			for (int j = blockBox.getMinY(); j <= blockBox.getMaxY(); j++) {
				for (int k = blockBox.getMinX(); k <= blockBox.getMaxX(); k++) {
					BlockPos srcBlock = new BlockPos(k, j, i);
					BlockPos dstBlock = srcBlock.add(offset);
					CachedBlockPosition cachedBlockPosition = new CachedBlockPosition(world, srcBlock, false);
					BlockState blockState = cachedBlockPosition.getBlockState();
					if(blockState == null) {
						Messenger.m(ctx.getSource(), "r Region is unloaded");
						return 0;
					}
					world.setBlockState(dstBlock, blockState, 2);
				}
			}
		}
		return 1;
	}

	private int executeChal(CommandContext<ServerCommandSource> ctx) {
		if(bowInUse != 0){
			Messenger.m(ctx.getSource(), "r Challenge currently running");
			return 0;
		}
		ServerPlayerEntity player = ctx.getSource().getPlayer();
		chalCaller = player;
		assert player != null;
		Vec3d pos = player.getPos();
		ServerWorld world = ctx.getSource().getWorld();
		MinecraftServer server = ctx.getSource().getServer();
		ServerPlayerEntity ctfplayer = server.getPlayerManager().getPlayer("LiveOverflow");
		assert ctfplayer != null;
		if(!hasBow) {
			ctfplayer.giveItemStack(new ItemStack(Items.BOW));
			ctfplayer.giveItemStack(new ItemStack(Items.ARROW));
			hasBow = true;
		}
		((ServerPlayerEntityInterface)ctfplayer).getActionPack().start(EntityPlayerActionPack.ActionType.USE, EntityPlayerActionPack.Action.continuous());
		bowInUse = 20;
		return 1;
	}

	@Override
	public void registerCommands(CommandDispatcher<ServerCommandSource> dispatcher, final CommandRegistryAccess commandBuildContext) {
		LiteralArgumentBuilder<ServerCommandSource> cmd;
		cmd = literal("tp2"). // Create a tp command
				requires(ServerCommandSource::isExecutedByPlayer).
				then(argument("position", Vec3ArgumentType.vec3()).
				executes( (ctx) -> {
					ServerPlayerEntity player = ctx.getSource().getPlayer();
                    assert player != null;
					Vec3d pos = Vec3ArgumentType.getVec3(ctx, "position");
					player.teleport(player.getWorld(), pos.x, pos.y, pos.z, player.getYaw(), player.getPitch());
					return 1;
				}));
		dispatcher.register(cmd);

		cmd = literal("gmc").
				requires(ServerCommandSource::isExecutedByPlayer).
				executes( (ctx) -> {
					ServerPlayerEntity player = ctx.getSource().getPlayer();
                    assert player != null;
                    player.changeGameMode(GameMode.CREATIVE);
					return 1;
				});
		dispatcher.register(cmd);

		cmd = literal("gms").
				requires(ServerCommandSource::isExecutedByPlayer).
				executes( (ctx) -> {
					ServerPlayerEntity player = ctx.getSource().getPlayer();
					assert player != null;
					player.changeGameMode(GameMode.SURVIVAL);
					return 1;
				});
		dispatcher.register(cmd);

		cmd = literal("clone2").
				requires(ServerCommandSource::isExecutedByPlayer).
				then(argument("src1", BlockPosArgumentType.blockPos()).
				then(argument("src2", BlockPosArgumentType.blockPos()).
				then(argument("dst", BlockPosArgumentType.blockPos()).
				executes(this::executeClone))));
		dispatcher.register(cmd);

		cmd = literal("chal").
				requires(ServerCommandSource::isExecutedByPlayer).
				executes(this::executeChal);
		dispatcher.register(cmd);
	}

	@Override
	public SettingsManager extensionSettingsManager() {
		// this will ensure that our settings are loaded properly when world loads
		return mySettingManager;
	}

	@Override
	public void onPlayerLoggedIn(ServerPlayerEntity player) {
		LOGGER.info("Hello Carpet Mod. Someone joined!");
	}

	@Override
	public void onPlayerLoggedOut(ServerPlayerEntity player) {
		//
	}
}