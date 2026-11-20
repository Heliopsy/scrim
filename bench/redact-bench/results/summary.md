## Micro: redact throughput (MB/s, 1 MB = 10^6 bytes, single pinned CPU, median)

| set | body | Go petar-nfa | Go pgavlin-nfa | Go petar-dfa | Go coregx | Rust ac-auto | Rust ac-dfa | best Rust / best Go |
|---|---|---|---|---|---|---|---|---|
| 10 | 100k hits | 73.5 | 71.0 | 226.4 | 369.8 | 3,897 | 3,816 | 17.21x |
| 10 | 100k clean | 76.9 | 74.2 | 245.8 | 467.0 | 4,436 | 4,449 | 18.10x |
| 10 | 1m hits | 45.0 | 73.2 | 204.1 | 290.7 | 3,259 | 3,314 | 16.24x |
| 10 | 1m clean | 46.4 | 75.9 | 243.0 | 465.7 | 3,863 | 3,766 | 15.90x |
| 10 | 4m hits | 40.1 | 72.6 | 186.2 | 292.3 | 3,307 | 3,306 | 17.75x |
| 10 | 4m clean | 73.8 | 76.2 | 245.5 | 474.8 | 3,982 | 4,007 | 16.32x |
| 1000 | 100k hits | 54.0 | 53.8 | 201.9 | 207.2 | 120.7 | 357.9 | 1.77x |
| 1000 | 100k clean | 58.2 | 60.2 | 214.8 | 345.9 | 123.1 | 414.0 | 1.93x |
| 1000 | 1m hits | 53.3 | 54.3 | 166.5 | 73.9 | 118.7 | 301.1 | 1.81x |
| 1000 | 1m clean | 55.0 | 56.4 | 206.1 | 305.6 | 118.8 | 377.5 | 1.83x |
| 1000 | 4m hits | 52.2 | 53.6 | 128.7 | 41.2 | 115.9 | 247.5 | 1.92x |
| 1000 | 4m clean | 54.2 | 55.5 | 200.5 | 298.9 | 119.9 | 378.1 | 1.89x |
| 10000 | 100k hits | 27.6 | 27.6 | n/a | n/a | 87.7 | n/a | 3.17x |
| 10000 | 100k clean | 31.5 | 32.5 | n/a | n/a | 102.3 | n/a | 3.15x |
| 10000 | 1m hits | 27.9 | 28.0 | n/a | n/a | 97.1 | n/a | 3.46x |
| 10000 | 1m clean | 30.5 | 31.8 | n/a | n/a | 96.6 | n/a | 3.04x |
| 10000 | 4m hits | 29.4 | 27.1 | n/a | n/a | 95.2 | n/a | 3.24x |
| 10000 | 4m clean | 30.8 | 27.6 | n/a | n/a | 94.7 | n/a | 3.08x |

coregx is not leftmost-longest (earliest-end); it fails the round-trip and cross-check on one fixture, so it is excluded from 'best Go'. DFA engines are not run at 10k secrets (Go petar-dfa needs ~14 GB, Rust ac-dfa 3.4 GB).

## Micro: allocations per redact call

| set | body | Go petar-nfa allocs/op | Go petar-nfa B/op | Go petar-dfa allocs/op | Rust ac-auto allocs | Rust ac-auto bytes |
|---|---|---|---|---|---|---|
| 10 | 100k hits | 31 | 840 | 58 | 0 | 0 |
| 10 | 100k clean | 5 | 216 | 6 | 0 | 0 |
| 10 | 1m hits | 211 | 5,177 | 418 | 0 | 0 |
| 10 | 1m clean | 5 | 232 | 6 | 0 | 0 |
| 10 | 4m hits | 886 | 21,408 | 1,766 | 0 | 0 |
| 10 | 4m clean | 5 | 252 | 6 | 0 | 0 |
| 1000 | 100k hits | 22 | 625 | 40 | 0 | 0 |
| 1000 | 100k clean | 5 | 217 | 6 | 0 | 0 |
| 1000 | 1m hits | 244 | 5,964 | 484 | 0 | 0 |
| 1000 | 1m clean | 5 | 228 | 6 | 0 | 0 |
| 1000 | 4m hits | 872 | 21,072 | 1,740 | 0 | 0 |
| 1000 | 4m clean | 5 | 264 | 6 | 0 | 0 |
| 10000 | 100k hits | 23 | 650 | n/a | 0 | 0 |
| 10000 | 100k clean | 5 | 217 | n/a | 0 | 0 |
| 10000 | 1m hits | 238 | 5,832 | n/a | 0 | 0 |
| 10000 | 1m clean | 5 | 240 | n/a | 0 | 0 |
| 10000 | 4m hits | 886 | 21,408 | n/a | 0 | 0 |
| 10000 | 4m clean | 6 | 288 | n/a | 0 | 0 |

Go output buffers come from a sync.Pool; Rust reuses one Vec. Go allocations are inside the AC libraries' iterators (one *Match per match plus iterator state).

## Micro: SSE restore (secret set 1000)

| stream | chunks | Go µs/stream | Go µs/chunk | Go MB/s | Go allocs/stream | Rust µs/stream | Rust µs/chunk | Rust MB/s | Rust allocs/stream | Go/Rust time |
|---|---|---|---|---|---|---|---|---|---|---|
| 2k | 134 | 3,219 | 24.02 | 80.6 | 15,951 | 717.1 | 5.35 | 361.9 | 2185 | 4.49x |
| 20k | 1258 | 31,497 | 25.04 | 81.4 | 157,150 | 7,184 | 5.71 | 356.9 | 21919 | 4.38x |

## Micro: automaton build

| set | lang | engine | build ms (one-shot) | build ms (bench median) | retained heap MB | peak RSS MB |
|---|---|---|---|---|---|---|
| 10 | go | petar-nfa | 32.5 | 8.4 | 2.2 | 12.0 |
| 10 | go | pgavlin-nfa | 31.6 | 8.0 | 2.2 | 11.1 |
| 10 | go | petar-dfa | 283.3 | 175.9 | 13.9 | 41.5 |
| 10 | go | coregx | 61.2 | 15.3 | 10.4 | 25.1 |
| 10 | rust | ac-auto (DFA) | 30.5 | 9.7 | 10.3 | 13.5 |
| 10 | rust | ac-dfa (DFA) | 15.1 | 9.8 | 10.3 | 13.5 |
| 1000 | go | petar-nfa | 529.1 | 438.0 | 66.7 | 184.7 |
| 1000 | go | pgavlin-nfa | 577.9 | 437.6 | 66.7 | 184.3 |
| 1000 | go | petar-dfa | 6,756 | 6,007 | 610.1 | 1,426 |
| 1000 | go | coregx | 1,450 | 1,134 | 348.8 | 755.2 |
| 1000 | rust | ac-auto (ContiguousNFA) | 84.2 | 79.2 | 8.8 | 38.7 |
| 1000 | rust | ac-dfa (DFA) | 759.3 | 782.8 | 345.2 | 370.1 |
| 10000 | go | petar-nfa | 5,882 | 6,173 | 618.7 | 1,423 |
| 10000 | go | pgavlin-nfa | 6,014 | 6,061 | 618.7 | 1,424 |
| 10000 | rust | ac-auto (ContiguousNFA) | 1,111 | 1,119 | 77.8 | 333.6 |
| 10000 | rust | ac-dfa (DFA) | 9,716 | n/a | 3,204 | 3,419 |

## x86-64-v2 vs v3 (subset)

| benchmark | Go v3 MB/s | Go v2 MB/s | Rust v3 MB/s | Rust v2 MB/s |
|---|---|---|---|---|
| Rust ac-auto set=10 1m hits | | | 3,259 | 3,288 |
| Rust ac-auto set=1000 1m hits | | | 118.7 | 113.7 |
| Rust ac-auto set=10000 1m hits | | | 97.1 | 94.0 |

## Proxy level (main run)

Dictionary: 10000 secrets; response fixture `stream-proxy-s10000`; medians over repetitions. Latency = full request incl. streamed response (oha). Added = target minus direct-to-upstream at the same load.

| scenario | conc | target | ok req | req/s | p50 ms | p99 ms | p999 ms | added p50 | added p99 | added p999 | TTFB p50 | CPU s/GB (proxy) | CPU s/GB (+cp) | peak RSS MB (proxy) | cp RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| paced | 10 | direct | 380 | 31.7 | 311.6 | 316.2 | 316.3 | n/a | n/a | n/a | 0.3 | 11.20 |  | 11.1 |  |
| paced | 10 | go | 360 | 30.0 | 327.0 | 373.1 | 375.9 | 15.4 | 56.9 | 59.6 | 11.9 | 96.00 |  | 1,569 |  |
| paced | 10 | rust | 370 | 30.8 | 320.0 | 328.0 | 331.0 | 8.4 | 11.8 | 14.7 | 5.2 | 41.97 |  | 334.2 |  |
| paced | 10 | combo-async | 370 | 30.8 | 320.5 | 339.2 | 345.1 | 8.9 | 23.0 | 28.8 | 5.1 | 191.70 | 192.43 | 456.5 | 83.5 |
| paced | 10 | combo-nodiff | 365 | 30.4 | 320.9 | 342.5 | 347.6 | 9.3 | 26.3 | 31.3 | 5.7 | 39.62 | 39.90 | 363.5 | 83.9 |
| paced | 10 | combo-syncaudit | 370 | 30.8 | 320.6 | 332.2 | 335.6 | 9.0 | 16.0 | 19.3 | 5.0 | 196.02 | 196.94 | 444.7 | 80.6 |
| paced | 10 | combo-grant | 370 | 30.8 | 321.5 | 332.4 | 335.4 | 10.0 | 16.2 | 19.1 | 5.6 | 203.38 | 204.49 | 445.5 | 86.7 |
| paced | 100 | direct | 3,750 | 312.4 | 313.9 | 351.4 | 363.7 | n/a | n/a | n/a | 0.4 | 6.20 |  | 14.3 |  |
| paced | 100 | go | 3,572 | 297.6 | 322.7 | 520.2 | 562.4 | 8.7 | 168.8 | 198.8 | 11.2 | 50.42 |  | 1,549 |  |
| paced | 100 | rust | 3,700 | 308.3 | 317.8 | 414.5 | 426.4 | 3.9 | 63.1 | 62.7 | 5.3 | 24.76 |  | 334.4 |  |
| paced | 100 | combo-async | 3,700 | 308.2 | 317.7 | 433.5 | 446.0 | 3.8 | 82.1 | 82.4 | 4.7 | 36.44 | 36.67 | 467.0 | 84.5 |
| paced | 100 | combo-nodiff | 3,700 | 308.2 | 317.7 | 416.7 | 429.6 | 3.8 | 65.3 | 65.9 | 5.0 | 24.20 | 24.42 | 364.1 | 84.1 |
| paced | 100 | combo-syncaudit | 3,700 | 308.2 | 318.5 | 401.3 | 418.8 | 4.6 | 49.9 | 55.1 | 4.8 | 36.96 | 37.51 | 467.6 | 84.3 |
| paced | 100 | combo-grant | 3,655 | 304.5 | 319.4 | 431.9 | 434.0 | 5.5 | 80.5 | 70.3 | 6.9 | 40.02 | 40.80 | 472.7 | 86.8 |
| paced | 1000 | direct | 34,058 | 2,835 | 343.2 | 451.4 | 475.5 | n/a | n/a | n/a | 0.6 | 4.51 |  | 57.4 |  |
| paced | 1000 | go | 9,024 | 751.2 | 1,221 | 2,247 | 2,833 | 877.3 | 1,795 | 2,357 | 1,217 | 36.94 |  | 2,890 |  |
| paced | 1000 | rust | 22,930 | 1,909 | 468.9 | 1,687 | 2,208 | 125.7 | 1,236 | 1,733 | 79.2 | 13.57 |  | 335.1 |  |
| paced | 1000 | combo-async | 18,661 | 1,554 | 563.9 | 1,752 | 2,470 | 220.7 | 1,300 | 1,994 | 93.6 | 17.05 | 17.18 | 734.9 | 86.6 |
| paced | 1000 | combo-nodiff | 22,034 | 1,834 | 475.3 | 1,603 | 1,772 | 132.1 | 1,151 | 1,297 | 80.0 | 13.93 | 14.05 | 383.3 | 84.9 |
| paced | 1000 | combo-syncaudit | 17,990 | 1,498 | 577.7 | 1,731 | 3,887 | 234.4 | 1,280 | 3,412 | 91.3 | 17.44 | 17.92 | 702.9 | 88.7 |
| paced | 1000 | combo-grant | 18,106 | 1,507 | 594.5 | 1,766 | 2,792 | 251.2 | 1,315 | 2,317 | 124.8 | 17.60 | 18.16 | 733.4 | 81.8 |
| unpaced-1m | 10 | direct | 99,700 | 12,459 | 0.6 | 6.3 | 13.7 | n/a | n/a | n/a | 0.5 | 0.30 |  | 12.2 |  |
| unpaced-1m | 10 | go | 819 | 102.3 | 93.1 | 165.3 | 289.9 | 92.5 | 159.0 | 276.2 | 93.0 | 35.68 |  | 1,578 |  |
| unpaced-1m | 10 | rust | 2,398 | 299.7 | 30.1 | 55.0 | 61.7 | 29.6 | 48.7 | 48.0 | 26.4 | 12.21 |  | 334.7 |  |
| unpaced-1m | 10 | combo-async | 1,898 | 237.2 | 40.5 | 74.8 | 84.7 | 39.9 | 68.5 | 71.0 | 30.8 | 15.49 | 15.53 | 483.8 | 84.9 |
| unpaced-1m | 10 | combo-nodiff | 2,330 | 291.1 | 30.4 | 57.0 | 71.3 | 29.8 | 50.8 | 57.6 | 27.3 | 12.51 | 12.54 | 364.0 | 84.7 |
| unpaced-1m | 100 | direct | 119,605 | 14,945 | 1.2 | 39.4 | 57.9 | n/a | n/a | n/a | 1.0 | 0.31 |  | 21.2 |  |
| unpaced-1m | 100 | go | 734 | 91.7 | 995.6 | 2,177 | 2,646 | 994.4 | 2,137 | 2,588 | 994.5 | 41.04 |  | 1,487 |  |
| unpaced-1m | 100 | rust | 2,162 | 270.2 | 353.2 | 844.7 | 1,038 | 352.0 | 805.3 | 980.2 | 156.3 | 13.54 |  | 334.3 |  |
| unpaced-1m | 100 | combo-async | 1,875 | 234.3 | 374.0 | 952.0 | 1,108 | 372.9 | 912.6 | 1,050 | 177.7 | 15.72 | 15.76 | 625.4 | 86.9 |
| unpaced-1m | 100 | combo-nodiff | 2,152 | 268.9 | 346.0 | 824.7 | 957.1 | 344.9 | 785.3 | 899.2 | 154.4 | 13.61 | 13.64 | 363.8 | 84.7 |
| unpaced-1m | 100 | combo-syncaudit | 1,774 | 221.7 | 419.7 | 1,007 | 1,094 | 418.5 | 968.1 | 1,036 | 191.6 | 16.64 | 16.72 | 648.2 | 88.5 |
| unpaced-1m | 100 | combo-grant | 1,832 | 228.9 | 407.5 | 891.6 | 1,027 | 406.3 | 852.3 | 969.5 | 191.6 | 16.10 | 16.22 | 667.3 | 80.6 |
| unpaced-1m | 1000 | direct | 120,056 | 14,991 | 4.5 | 541.2 | 862.4 | n/a | n/a | n/a | 4.2 | 0.35 |  | 66.5 |  |
| unpaced-1m | 1000 | go | 10 | 1.2 | 6,419 | 7,017 | 7,017 | 6,414 | 6,476 | 6,155 | 6,419 | 5,925 |  | 3,056 |  |
| unpaced-1m | 1000 | rust | 1,417 | 176.9 | 4,005 | 7,079 | 7,385 | 4,001 | 6,538 | 6,523 | 1,638 | 20.63 |  | 1,144 |  |
| unpaced-1m | 1000 | combo-async | 979 | 122.2 | 4,931 | 7,880 | 7,982 | 4,927 | 7,339 | 7,120 | 1,764 | 30.14 | 30.17 | 1,455 | 83.6 |
| unpaced-1m | 1000 | combo-nodiff | 1,428 | 178.3 | 4,240 | 7,175 | 7,799 | 4,235 | 6,634 | 6,936 | 1,870 | 20.42 | 20.44 | 1,191 | 86.4 |
| unpaced-1m-clean | 100 | direct | 116,970 | 14,616 | 1.2 | 40.6 | 61.6 | n/a | n/a | n/a | 1.0 | 0.32 |  | 20.7 |  |
| unpaced-1m-clean | 100 | go | 817 | 102.1 | 900.3 | 1,723 | 2,075 | 899.1 | 1,683 | 2,014 | 899.9 | 36.60 |  | 1,587 |  |
| unpaced-1m-clean | 100 | rust | 2,213 | 276.5 | 345.4 | 829.8 | 921.7 | 344.3 | 789.2 | 860.1 | 152.8 | 13.12 |  | 334.4 |  |
| unpaced-1m-clean | 100 | combo-async | 1,892 | 236.4 | 394.1 | 982.9 | 1,251 | 392.9 | 942.3 | 1,189 | 171.2 | 15.55 | 15.58 | 569.0 | 83.6 |
| unpaced-1m-clean | 100 | combo-nodiff | 2,148 | 268.4 | 346.3 | 846.0 | 941.3 | 345.1 | 805.4 | 879.7 | 150.5 | 13.53 | 13.56 | 364.0 | 83.0 |

## Proxy level (secondary run, 1000-secret dictionary)

Dictionary: 1000 secrets; response fixture `stream-proxy`; medians over repetitions. Latency = full request incl. streamed response (oha). Added = target minus direct-to-upstream at the same load.

| scenario | conc | target | ok req | req/s | p50 ms | p99 ms | p999 ms | added p50 | added p99 | added p999 | TTFB p50 | CPU s/GB (proxy) | CPU s/GB (+cp) | peak RSS MB (proxy) | cp RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| paced | 10 | direct | 380 | 31.7 | 311.0 | 314.3 | 314.7 | n/a | n/a | n/a | 0.3 | 10.28 |  | 11.2 |  |
| paced | 10 | go | 370 | 30.8 | 318.3 | 324.0 | 324.7 | 7.3 | 9.7 | 10.0 | 3.1 | 40.79 |  | 1,428 |  |
| paced | 10 | rust | 370 | 30.8 | 319.1 | 325.7 | 328.9 | 8.1 | 11.4 | 14.2 | 4.1 | 31.87 |  | 38.6 |  |
| paced | 100 | direct | 3,800 | 316.6 | 312.3 | 329.9 | 333.1 | n/a | n/a | n/a | 0.3 | 6.38 |  | 13.5 |  |
| paced | 100 | go | 3,700 | 308.3 | 316.2 | 388.6 | 398.4 | 3.9 | 58.7 | 65.3 | 2.9 | 23.25 |  | 1,441 |  |
| paced | 100 | rust | 3,700 | 308.2 | 317.5 | 401.2 | 411.0 | 5.3 | 71.3 | 77.9 | 4.3 | 18.77 |  | 42.1 |  |
| unpaced-1m | 10 | direct | 92,326 | 11,539 | 0.7 | 5.0 | 17.1 | n/a | n/a | n/a | 0.6 | 0.31 |  | 12.4 |  |
| unpaced-1m | 10 | go | 3,598 | 449.6 | 19.6 | 54.7 | 73.9 | 18.9 | 49.6 | 56.8 | 19.5 | 8.02 |  | 1,426 |  |
| unpaced-1m | 10 | rust | 2,655 | 331.7 | 28.8 | 50.9 | 72.7 | 28.1 | 45.8 | 55.6 | 23.2 | 11.01 |  | 55.6 |  |
| unpaced-1m | 100 | direct | 116,845 | 14,600 | 1.2 | 40.7 | 60.4 | n/a | n/a | n/a | 1.0 | 0.31 |  | 20.3 |  |
| unpaced-1m | 100 | go | 2,489 | 310.9 | 228.4 | 1,045 | 1,429 | 227.2 | 1,004 | 1,368 | 227.4 | 10.32 |  | 1,571 |  |
| unpaced-1m | 100 | rust | 1,355 | 169.3 | 410.5 | 2,478 | 3,073 | 409.4 | 2,437 | 3,013 | 171.9 | 15.06 |  | 203.0 |  |
| unpaced-1m-clean | 100 | direct | 25,660 | 3,206 | 5.1 | 259.9 | 408.9 | n/a | n/a | n/a | 4.5 | 0.49 |  | 23.6 |  |
| unpaced-1m-clean | 100 | go | 4,465 | 558.0 | 128.7 | 478.2 | 827.2 | 123.7 | 218.3 | 418.3 | 128.5 | 6.53 |  | 1,462 |  |
| unpaced-1m-clean | 100 | rust | 2,544 | 317.8 | 288.5 | 690.0 | 870.8 | 283.4 | 430.1 | 461.9 | 121.6 | 11.39 |  | 147.1 |  |

## Combo arm: boundary details (control plane in Go over UDS, length-prefixed JSON frames)

| scenario | conc | variant | audit events | events/s | UDS in MB/s | batches | drops | grant RTT p50/p99 ms | req p99 outside rebuild | req p99 during rebuild | n during | cp CPU s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| paced | 10 | combo-async r0 | 370 | 32.0 | 0.012 | 145 | 0 |  | 324.7 | 330.6 | 286 | 0.04 |
| paced | 10 | combo-nodiff r0 | 370 | 32.1 | 0.012 | 110 | 0 |  | 324.9 | 0.0 | 0 | 0.02 |
| paced | 10 | combo-syncaudit r0 | 370 | 32.0 | 0.012 | 0 | 0 |  | 323.7 | 329.3 | 315 | 0.05 |
| paced | 10 | combo-grant r0 | 370 | 31.9 | 0.014 | 120 | 0 | 0.133 / 4.873 | 326.3 | 328.4 | 326 | 0.06 |
| paced | 100 | combo-async r0 | 3700 | 320.5 | 0.118 | 421 | 0 |  | 325.4 | 376.6 | 3093 | 0.13 |
| paced | 100 | combo-nodiff r0 | 3700 | 319.6 | 0.117 | 495 | 0 |  | 372.5 | 0.0 | 0 | 0.13 |
| paced | 100 | combo-syncaudit r0 | 3700 | 319.5 | 0.119 | 0 | 0 |  | 320.9 | 364.4 | 3051 | 0.30 |
| paced | 100 | combo-grant r0 | 3655 | 313.9 | 0.139 | 694 | 0 | 0.790 / 20.537 | 325.1 | 382.4 | 3373 | 0.42 |
| paced | 1000 | combo-async r0 | 18116 | 1,555 | 0.574 | 514 | 0 |  | 484.4 | 762.2 | 17849 | 0.30 |
| paced | 1000 | combo-nodiff r0 | 21910 | 1,878 | 0.692 | 595 | 0 |  | 571.4 | 0.0 | 0 | 0.34 |
| paced | 1000 | combo-syncaudit r0 | 18053 | 1,548 | 0.577 | 0 | 0 |  | 341.3 | 698.0 | 17812 | 1.25 |
| paced | 1000 | combo-grant r0 | 18120 | 1,554 | 0.694 | 447 | 0 | 38.424 / 108.084 | 465.5 | 764.2 | 17495 | 1.49 |
| unpaced-1m | 10 | combo-async r0 | 1959 | 246.6 | 0.087 | 381 | 0 |  | 50.2 | 67.6 | 1734 | 0.09 |
| unpaced-1m | 10 | combo-nodiff r0 | 2350 | 296.4 | 0.105 | 427 | 0 |  | 55.5 | 0.0 | 0 | 0.08 |
| unpaced-1m | 100 | combo-async r0 | 1916 | 245.9 | 0.088 | 243 | 0 |  | 380.9 | 917.1 | 1790 | 0.07 |
| unpaced-1m | 100 | combo-nodiff r0 | 2239 | 288.9 | 0.103 | 250 | 0 |  | 707.3 | 0.0 | 0 | 0.06 |
| unpaced-1m | 100 | combo-syncaudit r0 | 1788 | 234.2 | 0.084 | 0 | 0 |  | 613.6 | 932.2 | 1355 | 0.14 |
| unpaced-1m | 100 | combo-grant r0 | 1832 | 239.3 | 0.104 | 216 | 0 | 40.884 / 238.992 | 458.7 | 889.8 | 1630 | 0.24 |
| unpaced-1m | 1000 | combo-async r0 | 919 | 121.7 | 0.044 | 96 | 0 |  | 0.0 | 6,677 | 919 | 0.03 |
| unpaced-1m | 1000 | combo-nodiff r0 | 1394 | 175.7 | 0.063 | 98 | 0 |  | 5,682 | 0.0 | 0 | 0.03 |
| unpaced-1m-clean | 100 | combo-async r0 | 1928 | 244.1 | 0.072 | 238 | 0 |  | 447.4 | 949.2 | 1778 | 0.08 |
| unpaced-1m-clean | 100 | combo-nodiff r0 | 2129 | 272.5 | 0.080 | 261 | 0 |  | 827.7 | 0.0 | 0 | 0.05 |
| paced | 10 | combo-async r1 | 370 | 32.0 | 0.012 | 135 | 0 |  | 323.3 | 331.4 | 304 | 0.04 |
| paced | 10 | combo-nodiff r1 | 360 | 31.5 | 0.012 | 135 | 0 |  | 355.1 | 0.0 | 0 | 0.01 |
| paced | 100 | combo-async r1 | 3700 | 321.2 | 0.118 | 475 | 0 |  | 320.7 | 384.3 | 2844 | 0.12 |
| paced | 100 | combo-nodiff r1 | 3700 | 320.0 | 0.118 | 430 | 0 |  | 360.8 | 0.0 | 0 | 0.11 |
| paced | 1000 | combo-async r1 | 19216 | 1,649 | 0.608 | 535 | 0 |  | 469.6 | 721.7 | 18434 | 0.38 |
| paced | 1000 | combo-nodiff r1 | 22175 | 1,903 | 0.702 | 658 | 0 |  | 532.7 | 0.0 | 0 | 0.43 |
| unpaced-1m | 10 | combo-async r1 | 1839 | 231.8 | 0.082 | 357 | 0 |  | 56.5 | 74.6 | 1671 | 0.07 |
| unpaced-1m | 10 | combo-nodiff r1 | 2309 | 290.5 | 0.103 | 406 | 0 |  | 55.5 | 0.0 | 0 | 0.08 |
| unpaced-1m | 100 | combo-async r1 | 1840 | 233.6 | 0.083 | 237 | 0 |  | 688.5 | 960.7 | 1502 | 0.08 |
| unpaced-1m | 100 | combo-nodiff r1 | 2067 | 266.2 | 0.095 | 252 | 0 |  | 873.7 | 0.0 | 0 | 0.05 |
| unpaced-1m | 1000 | combo-async r1 | 1044 | 145.9 | 0.052 | 106 | 0 |  | 0.0 | 6,347 | 1044 | 0.03 |
| unpaced-1m | 1000 | combo-nodiff r1 | 1477 | 186.6 | 0.067 | 120 | 0 |  | 5,163 | 0.0 | 0 | 0.03 |
| unpaced-1m-clean | 100 | combo-async r1 | 1859 | 239.2 | 0.070 | 239 | 0 |  | 409.1 | 955.4 | 1782 | 0.06 |
| unpaced-1m-clean | 100 | combo-nodiff r1 | 2170 | 273.2 | 0.080 | 271 | 0 |  | 793.2 | 0.0 | 0 | 0.07 |

Dictionary sync:

| push | secrets | payload bytes | CP encode ms | DP decode ms | DP automaton build ms | send -> live ms |
|---|---|---|---|---|---|---|
| full (start) | 10100 | 16,022,743 | 69.9 | 37.4 | 1,254 | 1,306 |
| diff (every 2 s, n=108) | 100 | 75,256 | 0.4 | 1.6 | 1,493 (p max 2,546) | 1,549 |

A diff triggers a full automaton rebuild (aho-corasick has no incremental insert) on a tokio blocking thread; the old snapshot keeps serving until an atomic swap.

## Decision rule evaluation

| load (unpaced 1 MB) | Go CPU s/GB | Rust CPU s/GB | Go/Rust | combo-async (+cp) s/GB | Go/combo | Go p99 | Rust p99 | combo p99 |
|---|---|---|---|---|---|---|---|---|
| c=10 | 35.68 | 12.21 | 2.92x | 15.53 | 2.30x | 165.3 | 55.0 | 74.8 |
| c=100 | 41.04 | 13.54 | 3.03x | 15.76 | 2.60x | 2,177 | 844.7 | 952.0 |
| c=1000 | 5,925 | 20.63 | 287.15x | 30.17 | 196.37x | 7,017 | 7,079 | 7,880 |

<!-- generated by harness/report.py -->
