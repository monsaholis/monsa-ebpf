# example tc_classifier

TC (Traffic Control) classifier to count packets.

## Build
```bash
cd examples/network/tc
./build.sh
```

## Attach
Replace `<IFACE>` with network interface:
```bash
sudo tc qdisc add dev <IFACE> clsact
sudo tc filter add dev <IFACE> ingress bpf obj build/example_tc_classifier.bpf.o sec classifier
```

## Detach
```bash
sudo tc qdisc del dev <IFACE> clsact
```
