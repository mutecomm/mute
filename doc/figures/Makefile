all: architecture.svg \
     architecture.pdf \
     messageflow.svg  \
     messageflow.pdf

# conversion with ASCIIToSVG
# https://github.com/imatix/zguide/tree/master/bin/asciitosvg
%.svg: %.txt
	a2s -i$< -o$@

%.pdf: %.svg
	inkscape --export-pdf=$@ $<
