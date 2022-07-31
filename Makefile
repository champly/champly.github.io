# THEME ?= keep
# THEME_REPO ?= https://github.com/XPoet/hexo-theme-keep
THEME ?= next
THEME_REPO ?= https://github.com/next-theme/hexo-theme-next
THEME_DIR ?= themes/${THEME}

run: install-theme
	hexo server

install-theme:
	$(call download-theme,${THEME_REPO},${THEME_DIR})
	cp -r images/* themes/${THEME}/source/images/

define download-theme
@[ -d $(2) ] || { \
set -e ;\
echo "Downloading $(1) => $(2)" ;\
git clone $1 $2;\
}
endef
