package com.challenge.mixin;

import carpet.patches.EntityPlayerMPFake;
import net.minecraft.block.BlockState;
import net.minecraft.block.Blocks;
import net.minecraft.block.entity.SignBlockEntity;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerPlayerEntity;
import net.minecraft.server.world.ServerWorld;
import net.minecraft.text.Text;
import net.minecraft.util.math.BlockPos;
import net.minecraft.world.GameMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import java.util.Random;

@Mixin(MinecraftServer.class)
public class InitMixin {
	private static final Logger LOGGER = LoggerFactory.getLogger("InitMixin");
	@Inject(at = @At("TAIL"), method = "loadWorld")
	private void init(CallbackInfo info) {
		MinecraftServer server = (MinecraftServer)(Object)this;

		Random random = new Random();
		int bounds = 100000;
		int x = random.nextInt(-bounds,bounds);
		int y = 200;
		int z = random.nextInt(-bounds,bounds);
		BlockPos goalPos = new BlockPos(x, y, z);
		EntityPlayerMPFake.createFake(
			"LiveOverflow",
			server,
			goalPos.getX(), goalPos.getY(), goalPos.getZ(),
			0, 90,
			server.getOverworld().getRegistryKey(),
			GameMode.CREATIVE,
			true
		);

		ServerWorld world = server.getOverworld();
		world.setBlockState(goalPos.down(1), Blocks.GLASS.getDefaultState());
		world.setBlockState(goalPos, Blocks.OAK_SIGN.getDefaultState());
		SignBlockEntity sign = (SignBlockEntity)world.getBlockEntity(goalPos);
        assert sign != null;
		String flag = System.getenv("FLAG");
		if(flag == null){
			flag = "idekCTF{placeholder}";
		}
		for(int i=0; i<3; i++){
			int s = 16*i;
			int e = Math.min(16*i + 16, flag.length());
			if (s>=e) break;
			sign.setTextOnRow(i, Text.literal(flag.substring(s, e)));
		}
        ServerPlayerEntity player = server.getPlayerManager().getPlayer("LiveOverflow");
		LOGGER.info("Player spawned at {} {} {}", x, y, z);
		LOGGER.info("Mixin called");
	}
}