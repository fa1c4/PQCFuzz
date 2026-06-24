BUILD_DIR ?= .
BUILD_DIR := $(abspath $(BUILD_DIR))
CPU_FEATURES_BUILD_DIR := $(BUILD_DIR)/cpu_features
CPU_FEATURES_LIB := $(CPU_FEATURES_BUILD_DIR)/libcpu_features.a

all : $(BUILD_DIR)/cryptofuzz $(BUILD_DIR)/generate_dict $(BUILD_DIR)/generate_corpus

CXXFLAGS += -Wall -Wextra -std=c++17 -I $(BUILD_DIR) -I include/ -I . -I fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL
REPOSITORY_STAMP = $(BUILD_DIR)/repository.stamp
REPOSITORY_HEADERS = $(BUILD_DIR)/repository_tbl.h $(BUILD_DIR)/repository_map.h
OBJECT_NAMES = \
bignum_fuzzer_importer.o botan_importer.o builtin_tests_importer.o components.o crypto.o datasource.o driver.o \
ecc_diff_fuzzer_exporter.o ecc_diff_fuzzer_importer.o entry.o executor.o expmod.o mutator.o mutatorpool.o numbers.o \
openssl_importer.o operation.o options.o repository.o tests.o util.o wycheproof.o z3.o
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

$(BUILD_DIR)/cryptofuzz : $(OBJECT_FILES) $(CPU_FEATURES_LIB)
	test $(LIBFUZZER_LINK)
	$(CXX) $(CXXFLAGS) $(OBJECT_FILES) $(MODULE_ARCHIVES) $(LIBFUZZER_LINK) $(CPU_FEATURES_LIB) $(LINK_FLAGS) -o $@

$(BUILD_DIR)/generate_dict: generate_dict.cpp $(BUILD_DIR)/repository_map.h | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) generate_dict.cpp -o $@

$(BUILD_DIR)/generate_corpus: generate_corpus.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) generate_corpus.cpp -o $@

clean:
	rm -rf $(OBJECT_FILES) $(REPOSITORY_HEADERS) $(REPOSITORY_STAMP) $(BUILD_DIR)/cryptofuzz $(BUILD_DIR)/generate_dict $(BUILD_DIR)/generate_corpus $(CPU_FEATURES_BUILD_DIR)
