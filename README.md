# ElectronRipper ⚡

<!-- Python logo -->
<a href="https://www.python.org" target="_blank"> <img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/python/python-original.svg" alt="python" width="40" height="40"/> </a>

<img src="./img/banner.jpg">

## Forked 09/06/2024

This repository is a fork of the repository: <a href="https://github.com/rarecoil/unwebpack-sourcemap">UnwebpackSourcemap</a> and I will continue to bring updates and improvements over time. I will create a guide on how you, the user, can help me bring new updates and improvements. Thank you for using this tool.

### Recover uncompiled TypeScript sources, JSX, and more from Webpack sourcemaps.

As single-page applications take over the world, more and more is being asked of the browser as a client. It is common for SPAs to use [Webpack](https://webpack.js.org/) to handle browser script build processes. Usually, Webpack will transpile React/Vue/TypeScript/etc. to JavaScript, minify/compress it, and then serve it as a single bundle to the application.

However, Webpack also produces [JavaScript source maps](https://www.html5rocks.com/en/tutorials/developertools/sourcemaps/) to assist in the debugging and development process; when things go wrong, the browser's debugger can use the SourceMap to point to a line in the code that contains the issue at hand. Most developers do not adequately protect the source maps and ship them to production environments.

When the browser was simply handling an array of JavaScript files concatenated and (maybe) packed, this wasn't so much of an issue. However, developers of SPAs assume the use of JavaScript as an **intermediate representation**. Developers often expect production to contain obfuscated and/or otherwise-processed scripts, and do not understand just what the sourcemaps contain in many cases. This model aligns closely with shipping binaries: source is compiled and you ship the interpretable version. If this is the case, the sourcemap is akin to leaking your source alongside the "binary" (bundle) you have made. The bundle can be reverse engineered just as a binary can, but sourcemaps make this far easier.


## Usage 

The script requires Python3, `BeautifulSoup4` and `requests`. Install dependencies with `pip3 install -r requirements.txt`. The script can handle downloaded sourcemaps, or attempt to parse them from remote sources for you. In all of these cases, we will assume that you have a directory you have created called `output` alongside the script:

```
\$ mkdir output
```

In order of increasing noisiness, to unpack a local sourcemap, remembering that you have to pass the absolute paths for the script to work.:

```
\$ python main.py --local 'C:\Users\Usuario\OneDrive\Documentos\ElectronRipper\Luna\resources\unpackedcopy\build\static\js\main.af54de98.js.map' -o 'C:\Users\Usuario\OneDrive\Documentos\ElectronRipper\test\resources\unpackedcopy\luna'
```

To unpack a remote sourcemap:

```
\$ ./main.py https://pathto.example.com/source.map output
```

To attempt to read all `<script src>` on an HTML page, fetch JS assets, look for `sourceMappingURI`, and pull sourcemaps from remote sources:

```
\$ ./main.py --detect https://pathto.example.com/spa_root/ output
```

## I'm a developer and this scares me. What do?

You have a few options:

1. Turn off sourcemaps in production entirely.
1. Push sourcemaps to a private server, and ACL sourcemap URIs to developers only.
1. Load sourcemaps from local sources only and do not push them to production.


## Example Vulnerable Application

An example TypeScript+React application is included in `example-react-ts-app`. You can run this locally and run the script against it.


## Contributions

This is an alpha-level script built for a series of engagements I was working on in which sourcemaps are disclosed in production environments. It currently is only meant to work with TypeScript+React and TypeScript+Vue templates. Pull requests to harden the script, make it read more sourcemaps, et cetera are greatly appreciated.


## License

MIT.
