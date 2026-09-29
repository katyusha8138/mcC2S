# Forge 1.20.1 アダプタ: FML が @Mod のクラスを走査してコンストラクタを呼ぶ。
# アダプタのパッケージはローダーの型と直接やり取りするので、名前を保つ。
-keep @net.minecraftforge.fml.common.Mod class * {
    <init>(...);
}
-keep class io.github.katyusha8138.mcc2s.forge.** {
    *;
}
