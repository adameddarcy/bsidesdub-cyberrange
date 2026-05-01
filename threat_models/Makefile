# Makefile for generating threat model outputs
# Requires: graphviz, plantuml (optional), pandoc (optional)

MODEL ?= cyber_range_tm
OUTPUT_DIR = output

.PHONY: all clean dfd seq report report-simple list-threats json docker-all

all: dfd report

$(OUTPUT_DIR):
	mkdir -p $(OUTPUT_DIR)

dfd: $(OUTPUT_DIR)
	python3 $(MODEL).py --dfd | dot -Tpng -o $(OUTPUT_DIR)/dfd.png
	@echo "Generated $(OUTPUT_DIR)/dfd.png"

seq: $(OUTPUT_DIR)
	python3 $(MODEL).py --seq | java -Djava.awt.headless=true -jar $(PLANTUML_PATH) -tpng -pipe > $(OUTPUT_DIR)/seq.png
	@echo "Generated $(OUTPUT_DIR)/seq.png"

report: dfd $(OUTPUT_DIR)
	python3 generate_report.py
	@echo "Generated $(OUTPUT_DIR)/report.html (interactive)"

report-simple: $(OUTPUT_DIR)
	python3 $(MODEL).py --report templates/report_template.md | pandoc -f markdown -t html --standalone > $(OUTPUT_DIR)/report-simple.html
	@echo "Generated $(OUTPUT_DIR)/report-simple.html"

list-threats:
	python3 $(MODEL).py --list

json: $(OUTPUT_DIR)
	python3 $(MODEL).py --json $(OUTPUT_DIR)/threats.json
	@echo "Generated $(OUTPUT_DIR)/threats.json"

docker-all:
	docker run --rm -v $(PWD):/data -w /data \
		--entrypoint /bin/bash \
		plantuml/plantuml -c "\
			pip install pytm && \
			mkdir -p output && \
			python3 $(MODEL).py --dfd | dot -Tpng -o output/dfd.png && \
			python3 $(MODEL).py --seq | java -Djava.awt.headless=true -jar /plantuml.jar -tpng -pipe > output/seq.png"

clean:
	rm -rf $(OUTPUT_DIR)
