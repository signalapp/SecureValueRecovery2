## Building the PDF

To build the pdf from source, you will need to install pdflatex and bibtex - the [TeXLive](https://www.tug.org/texlive/) distribution is probably the simplest way to do this. Alternatively tou can use an online system like [OVerleaf](https://overleaf.com) that will take care of most of the LaTeX related headaches for you.

With these installed, run the following commands:
```
pdflatex svr3.tex # produces initial pdf and computes references needed in svr3.aux
bibtex svr3 # builds bibliography
pdflatex svr3.tex # incorporates bilbiography into the pdf
```
If prompted for input during the last run of pdflatex, press "enter" to continue.
