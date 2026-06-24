BUILD_DIR ?= .
BUILD_DIR := $(abspath $(BUILD_DIR))
CPU_FEATURES_BUILD_DIR := $(BUILD_DIR)/cpu_features
CPU_FEATURES_LIB := $(CPU_FEATURES_BUILD_DIR)/libcpu_features.a

all : $(BUILD_DIR)/clfuzz

CXXFLAGS += -Wall -Wextra -std=c++17 -I $(BUILD_DIR) -I include/ -I . -I fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL
REPOSITORY_STAMP = $(BUILD_DIR)/repository.stamp
REPOSITORY_HEADERS = $(BUILD_DIR)/repository_tbl.h $(BUILD_DIR)/repository_map.h
OBJECT_NAMES = driver.o executor.o util.o entry.o tests.o operation.o datasource.o repository.o options.o components.o wycheproof.o crypto.o input_generator.o numbers.o recyclepool.o ecc_diff_fuzzer_importer.o botan_importer.o
OBJECT_FILES = $(addprefix $(BUILD_DIR)/,$(OBJECT_NAMES))
MODULE_ARCHIVES = $(shell find modules -type f -name module.a)

$(BUILD_DIR):
	mkdir -p $@

$(REPOSITORY_STAMP): gen_repository.py | $(BUILD_DIR)
	cd $(BUILD_DIR) && python3 $(abspath gen_repository.py)
	touch $@

$(REPOSITORY_HEADERS): $(REPOSITORY_STAMP)

$(BUILD_DIR)/%.o : %.cpp $(REPOSITORY_HEADERS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $< -c -o $@

$(BUILD_DIR)/numbers.o : numbers.cpp $(REPOSITORY_HEADERS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -O0 numbers.cpp -c -o $@

$(CPU_FEATURES_LIB) :
	rm -rf $(CPU_FEATURES_BUILD_DIR)
	mkdir -p $(CPU_FEATURES_BUILD_DIR)
	cd $(CPU_FEATURES_BUILD_DIR) && cmake $(abspath third_party/cpu_features) && make

$(BUILD_DIR)/clfuzz : $(OBJECT_FILES) $(CPU_FEATURES_LIB)
	test $(LIBFUZZER_LINK)
	$(CXX) $(CXXFLAGS) $(OBJECT_FILES) $(MODULE_ARCHIVES) $(LIBFUZZER_LINK) $(CPU_FEATURES_LIB) $(LINK_FLAGS) -o $@

clean:
	rm -rf $(OBJECT_FILES) $(REPOSITORY_HEADERS) $(REPOSITORY_STAMP) $(BUILD_DIR)/clfuzz $(CPU_FEATURES_BUILD_DIR)

cleanTxtMarks:
	rm -rf emptyResultCount.txt executionCount.txt runningCount.txt getModuleCount.txt getUnexistedModuleCount.txt getValidModuleCount.txt enterRunningCount.txt validResultCount.txt saved_seeds/*
