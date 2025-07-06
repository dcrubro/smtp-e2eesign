#!/bin/bash
kramdown-rfc2629 draft-jonaskorenenovak-smtp-e2eesign.md > draft.xml
xml2rfc draft.xml --text --html

