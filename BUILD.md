# Building FibrumPDF from source

FibrumPDF compiles a Go shared library against **MuPDF 1.27** and packages both
native runtimes inside a platform wheel. You need Go 1.24+, Python 3.11+, `uv`,
the MuPDF headers, and a matching shared MuPDF library.

Prebuilt wheels already contain these native components. Follow this guide only
for local development or a platform without a published wheel.

## 1. Get the headers

The repository pins MuPDF as a submodule:

```bash
git submodule update --init --recursive
```

Only `mupdf/include/` is required to compile the bridge.

## 2. Provide the MuPDF runtime

Create `lib/mupdf/` and place the runtime for the build platform there:

| Platform | Required files |
| --- | --- |
| Linux | `libmupdf.so.27.0` and a `libmupdf.so` symlink |
| macOS | `libmupdf.dylib` |
| Windows | `libmupdf.dll` and its runtime DLL dependencies |

The project's
[MuPDF prebuilt releases](https://github.com/aditbajaj/mupdf-prebuilts/releases/tag/mupdf-1.27.0)
contain the files used by CI. You can instead build MuPDF from the submodule:

```bash
cd mupdf
make shared=yes release=yes lib
```

Copy the resulting shared library into `lib/mupdf/` before continuing. The
library architecture must match the wheel architecture.

## 3. Build and test

On Linux, expose the runtime while installing and running:

```bash
export LD_LIBRARY_PATH="$PWD/lib/mupdf${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
uv sync --extra dev
uv build
uv run pytest -q

cd go
go test ./...
go vet ./...
```

Use `DYLD_LIBRARY_PATH` on macOS. On Windows, ensure `lib/mupdf` is on `PATH`
while building.

`uv build` invokes `setup.py`, which compiles `go/cmd/tojson` with
`-buildmode=c-shared`, copies the MuPDF runtime beside it, and creates one
Python-ABI-independent wheel for the current platform.

## Native-only development

To rebuild the bridge without creating a wheel:

```bash
cd go
go build -buildmode=c-shared -o /tmp/libtomd.so ./cmd/tojson
```

Point Python at that build for a local smoke test:

```bash
FIBRUMPDF_LIB=/tmp/libtomd.so \
  uv run fibrum-pdf test_data/pdfs/sample.pdf /tmp/sample.json
```

On macOS or Windows, use the platform library suffix in both commands.

## Troubleshooting

- `libtomd not found`: install the built wheel, or set `FIBRUMPDF_LIB` to the
  bridge's absolute path.
- MuPDF cannot be loaded: verify the runtime is beside the bridge or present in
  the platform library search path.
- Linker architecture errors: the Go toolchain, MuPDF runtime, and target wheel
  must all use the same architecture.
- Missing headers: initialize the submodule and confirm `mupdf/include/mupdf`
  exists.
