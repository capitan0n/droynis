# Shizuku starts ShellService in its own process and creates it by class name, so R8 must keep
# the class, its name and its no-argument constructor.
-keep class io.github.capitan0n.droynis.platform.shizuku.ShellService {
    public <init>();
}
