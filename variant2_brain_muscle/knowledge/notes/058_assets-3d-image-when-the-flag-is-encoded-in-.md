---
tags: Assets / 3D-image
source: distilled/writeup
---
When the flag is encoded in geometry (a 3D app / mesh), dump the vertex or mesh buffer from memory at the draw call (x32dbg), parse the floats with `struct`, and import the point cloud into Blender to read the shape. The rendering pipeline is the oracle — recover its input data, don't fight the shader.
