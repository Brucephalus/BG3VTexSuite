# BG3VTexSuite
Tools for manipulating virtual textures in Baldur's Gate 3
Baldur's Gate 3 virtual textures are made using the middleware Granite. This folder contains a (hopefully) cracked version of the Granite SDK. Let me know if it bugs on you. Be sure to also describe how it bugs; "it didn't work" doesn't help me search through binary. I am Brucephalus on Discord.
A cursory search suggests that I have fully unlocked the software, but it is possible that certain actions will prompt the software to fail for lack of license. If that happens, I will try to find the code responsible and excise it.

 1. Install Granite from Granite_Toolset_5.0.7_Setup_for_Public.exe, which can be downloaded at https://documentation.graphinesoftware.com/download/Granite_Toolset_5.0.7_Setup.exe
 2. Replace GrBuild.exe, TileSetViewer.exe, GrBuildStudio.exe, and Nixel.dll with the files of the same names from this folder.

Granite is no longer commercially available; Larian purchased a license before Granite disappeared from the market. The Granite runtime can be found within the Unity engine and within some games that use Granite.

I have collected what documentation I can find in this folder. GraphineSoftware also has a few YouTube videos that provide crumbs of information.

TileSetViewer allows you to open *.gts files.
GrBuild is a console application that allows you to create *.gtp and *.gts files. It uses *.grproj files.
GrBuildStudio uses *.grsln files.

The following are command line parameters for GrBuild.exe:

Usage: GrBuild <project> <Options>

Options:

  --new
     (-n) Specify if a new project file should be created

        Example: GrBuild.exe MyProject.gproj -n

  --verbosity <level>
     (-v) Display this amount of information in the event log.
        The available verbosity levels are:
        q[uiet], n[ormal], d[etailed]

        Example: --verbosity q or -v q

  --nofilelogger
     (-nolog) Disable logging build output to a file.
        By default the build output is logged to the file ProjectName.log.

  --delete <assset name>
     (-del) Delete an asset given the asset name.
        Use "all" to delete all assets (-del all)
        Example: --delete MyAsset or -del MyAsset

  --task <task name>
     (-task) Execute a build task. The available tasks are:
        build(default - build gts)
        rebuild (clean intermediate files first then build)
        clean (only clean intermediate files if any found).
        nobuild (don't build, only run necessary processes for import/delete)

        Example: --task rebuild or -t rebuild

  --importassets <path>
     (-i) Import all assets described in <file>.

        Example: --importassets myassets.xml or -i myassets.xml

  --exclusive
     (-e) Specifiy that the import is exclusive.
        Existing assets in the project that are not part of the xml file will be removed.
        This option only works in combination with the importassets option

        Example: --importassets assets.xml --exclusive or -i assets.xml -e

  --config <config name>
     (-c) Set the configuration to use. Configurations are:
        fast (default), optimized.
        Note that intermediary files in the build process are written to
        the config subfolder in the intermediary directory, e.g., './tmp/fast/pages.dat'

        Example: --config fast or -c fast

  --options name:value,name:value
     (-opt) Set extra options. See manual for extra options.

        Example: -opt "Tilingmode:Hardware,MaximumAnisotropy:8,Pagesize:65536"

  --output <path>
     (-o) Set output file path

        Example: -o "OutputFile.gts"

  --pagesdir <relative path>
     (-p) Set relative directory for storing the page files, start path with directory name.
        Example: -p "pages" or --pagesdir "somedir/otherdir"

  --gtexdir <relative path>
     (-g) Set relative directory for storing the gtex files, start path with directory name.
        Example: -g "GTEXFiles" or --gtexdir "somedir/otherdir"

  --buildprofile <profile name>
     (-pr) Set Build Profile to one of the available built-in profiles, set by name.
        Example: -pr "Default" or --profile "Default"

  --warninglevel value
     (-w) Set Warning Level between 1 and 3. See manual for summary of warning level conditions

Example: -w 2

  --nopatching
     (-np) Prevent GTex and GTS patching, never builds the GTS and GTex incrementally.

  --nouniformcoding
     (-nuu) Disable the use of special coding of uniform areas in a GTS (set to enable compatibility with older runtimes not supporing uniform coding).

  --strict
     (-str) Enable strict mode. Strict mode prevents certain features which can have unexpected side effects, such as automatic resizing of assets with changing aspect ratio, bit depth conversion, etc.

  --lightmapmode
     Undocumented

  --cleanincludegtex
     When cleaning (-t clean) also cleans the GTEX files.

  --cleanincludetileset
     When cleaning (-t clean) also cleans the tile set files (.gts and .gtp files).

  --forceusegtex
     Force using existing GTex files, even if the GTex files are out dated.

  --allowforeigngtex
     Allow the use of GTex files built by another project (use together with the 'forceusegtex' flag).

  --buildnotileset
     No GTS file is written by the tools. The build process ends after GTex files are created.

  --noredirection
     Disable redirection of tiles in the GTS.

  --nosharedmiptiles
     Disable shared mip tile generation when building the GTS.

  --nomipstripping
     Disable embedded mip stripping where a tile's mip if it resides in the same page as the tile, is only coded once

  --setguid value
     Set the GUID of the active project. Example: -forceguid "{0f8fad5b-d9cb-469f-a165-70867728950e}"

  --buildgtsforgtex
     Build a GTS file stripping where a tile's mip if it resides in the same page as the tile, is only coded once

  --version
     (-version) Display version information only.

  --help
     (-h) Display this use message.


This folder also contains BG3 granite project files, as taken directly from the tile sets.
