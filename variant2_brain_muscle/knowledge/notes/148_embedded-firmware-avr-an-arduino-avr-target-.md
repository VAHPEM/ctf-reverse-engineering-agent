---
tags: Embedded firmware / AVR
source: distilled/flareon
---
An Arduino/AVR target (an Intel-HEX `.hex` file, ATmega symbols, avrdude flashing) is reversed as AVR: load in radare2/IDA with the AVR processor, or emulate with simavr, to recover the logic. The 'answer' is often a hardware state (e.g. a digital-pin bit pattern) that the firmware checks — recover it statically and, if needed, flash it back with `avrdude -patmega328p -carduino`.
