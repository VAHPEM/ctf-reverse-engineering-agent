---
tags: Pixel / coordinate check
source: distilled/writeup
---
A WinProc/handler that computes coordinates from your input via `mod` constants is asking you to click one specific pixel: compute (x,y) = (f(input) % A, g(input) % B) from the code, then click exactly that point to trigger the flag.
