all: architecture.svg \
     architecture.pdf \
     messageflow.svg  \
     messageflow.pdf \
     alicebobeve.svg \
     alicebobnoeve.svg \
     keyserver.svg \
     evilkeyserver.svg \
     signingkeyserver.svg \
     pki.svg \
     pkiwitheve.svg \
     fingerprintidea.svg \
     fingerprintreality.svg \
     blockchain.svg \
     wot.svg \
     wotproblem.svg \
     trustless.svg \
     trustlessaction.svg \
     mutekeyd.svg

# conversion with ASCIIToSVG
# https://github.com/imatix/zguide/tree/master/bin/asciitosvg
%.svg: %.txt
	a2s -i$< -o$@

%.pdf: %.svg
	inkscape --export-pdf=$@ $<
