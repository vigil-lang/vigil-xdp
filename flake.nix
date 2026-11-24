# The tools of the examples (clang, libbpf, the kernel headers, Python) and
# one NixOS VM per kernel to run the differential test without root on the
# host: KVM only.
#
#   nix develop                  clang, libbpf, bpftool, python3, make
#   nix run .#vm-test            make objects, then tests/run.sh in a VM per
#                                kernel; KERNELS="linux_6_12" restricts
#
# The Vigil compiler is not built here: VIGIL names it (by default `vigil`
# on the PATH; see README.md to install it).
{
  description = "The examples of 'Fast Packet Processing with eBPF and XDP' in C and in Vigil";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/241313f4e8e508cb9b13278c2b0fa25b9ca27163";

  outputs =
    { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      lib = nixpkgs.lib;

      kernels = [
        "linux_5_15"
        "linux_6_1"
        "linux_6_6"
        "linux_6_12"
        "linux_6_18"
      ];

      clang = pkgs.llvmPackages.clang-unwrapped;
      tools = [
        clang
        pkgs.libbpf
        pkgs.bpftools
        pkgs.python3
        pkgs.gnumake
        pkgs.gcc
        pkgs.pkg-config
        pkgs.zlib
        pkgs.elfutils
      ];
      env = {
        LIBBPF = "${pkgs.libbpf}";
        KHEADERS = "${pkgs.linuxHeaders}";
        CLANG = "${clang}/bin/clang";
      };

      # A NixOS VM with a kernel that runs, as root, tests/run.sh in the
      # directory shared with it (SHARED_DIR, mounted at /tmp/shared), writes
      # its output to build/vm-KERNEL.log and powers off. It shares the
      # host's /nix/store, so the harness needs no copy.
      vm =
        kernel:
        (lib.nixosSystem {
          inherit system;
          modules = [
            "${nixpkgs}/nixos/modules/virtualisation/qemu-vm.nix"
            (
              { pkgs, ... }:
              {
                boot.kernelPackages = pkgs.linuxKernel.packages.${kernel};
                virtualisation = {
                  graphics = false;
                  memorySize = 2048;
                  cores = 2;
                  diskImage = null;
                };
                networking.hostName = "ebpf-xdp-vm";
                systemd.services.examples = {
                  wantedBy = [ "multi-user.target" ];
                  after = [ "multi-user.target" ];
                  serviceConfig.Type = "oneshot";
                  path = [
                    pkgs.bash
                    pkgs.coreutils
                    pkgs.gnugrep
                    pkgs.diffutils
                    pkgs.python3
                  ];
                  script = ''
                    cd /tmp/shared
                    bash tests/run.sh > build/vm-${kernel}.log 2>&1 || true
                    sync
                    poweroff -f
                  '';
                };
                system.stateVersion = "26.05";
              }
            )
          ];
        }).config.system.build.vm;

      vms = lib.listToAttrs (
        map (k: {
          name = "vm-${k}";
          value = vm k;
        }) kernels
      );

      vmTest = pkgs.writeShellScript "vm-test" ''
        set -eu
        export PATH=${lib.makeBinPath tools}:$PATH
        ${lib.concatStringsSep "\n" (lib.mapAttrsToList (k: v: "export ${k}=${v}") env)}
        make objects packets
        status=0
        for kernel in ''${KERNELS:-${lib.concatStringsSep " " kernels}}; do
          case $kernel in
          ${lib.concatMapStringsSep "\n" (k: "  ${k}) vm=${vm k} ;;") kernels}
            *) echo "unknown kernel $kernel"; exit 1 ;;
          esac
          rm -f build/vm-$kernel.log
          SHARED_DIR=$PWD timeout "''${VM_TIMEOUT:-1800}" $vm/bin/run-*-vm < /dev/null \
            > build/vm-$kernel.console 2>&1 || true
          echo "== $kernel"
          cat build/vm-$kernel.log 2>/dev/null || { echo "no log (see build/vm-$kernel.console)"; status=1; }
          grep -q '^ALL OK' build/vm-$kernel.log 2>/dev/null || status=1
        done
        exit $status
      '';
    in
    {
      packages.${system} = vms;

      devShells.${system}.default = pkgs.mkShell (
        {
          packages = tools;
        }
        // env
      );

      apps.${system}.vm-test = {
        type = "app";
        program = toString vmTest;
      };
    };
}
