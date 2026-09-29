# mcC2S 配布 jar の名前の難読化(ProGuard)。共通の設定。
#
# 方針
#   - 縮小・最適化はしない(挙動を変えない。難読化=名前の付け替えだけを行う)
#   - core / common(プロトコル・走査・検証)のクラス・メソッド・フィールドの名前を付け替える
#   - ローダーとの接点(アダプタのパッケージ)は名前を保つ。ローダー側の型を継承・実装していて、
#     ローダー(Minecraft / Forge / NeoForge)のクラスを ProGuard に与えない構成では、
#     オーバーライドの名前を安全に判定できないため。アダプタが呼ぶ core / common の名前は自動で付け替わる
#   - 入力・出力・ライブラリ・ローダー別のルールは、Gradle が生成する設定と loader 別ファイルで与える

-dontshrink
-dontoptimize
# ローダー(Minecraft / Forge / NeoForge / night-config)のクラスは与えないので、参照先が見つからない旨の警告は無視する。
# 参照先が未知のクラスの名前は、ProGuard は変更しない。
-dontwarn **
-dontnote **

# 付けておく属性。デバッグ情報は行番号だけ残し(不具合報告のスタックトレースに使う)、ソースファイル名は伏せる。
-keepattributes Signature,InnerClasses,EnclosingMethod,Exceptions,*Annotation*,AnnotationDefault,Record,PermittedSubclasses,NestHost,NestMembers,LineNumberTable
-renamesourcefileattribute mcC2S

# 名前を付け替えたクラスは 1 つのパッケージにまとめる(このパッケージは mcC2S 専用)
-repackageclasses io.github.katyusha8138.mcc2s.internal

# 例外クラスの名前は診断メッセージ(クライアントが「失敗: <例外名>」と表示する)に出るので保つ
-keepnames class * extends java.lang.Throwable

# 列挙型: values() / valueOf() は実行時に名前で引かれる
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# record: 成分のフィールド名は toString() 等の内部で使われるので保つ
-keepclassmembernames class * extends java.lang.Record {
    <fields>;
}
