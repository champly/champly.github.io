---
title: 使用 HEXO 构建 github 博客
---

如何使用 [Hexo](https://hexo.io/zh-cn/) 构建一个博客，并且使用 [github pages](https://pages.github.com/) 来展示

## Init blog

``` shell
npm install hexo-cli -g
hexo init blog
cd blog
npm install
hexo server
```

## Themes

可以在 [这里](https://hexo.io/themes/) 查看自己喜欢的主题，我使用的是 [keep](https://github.com/XPoet/hexo-theme-keep), 这个主题(对移动端也进行适配了的)，如果喜欢的话可以根据 [这个配置](https://keep-docs.xpoet.cn/usage-tutorial/configuration-guide.html) 配置成你想要的样式

## Github Setting

[使用 Github Actions 自动部署 Hexo 博客](https://printempw.github.io/use-github-actions-to-deploy-hexo-blog/), 这个就是我参考的一个文档，其中需要说明的一些点有如下的地方：

### ssh-keygen

**使用 `ssh-keygen` 生成密钥对的时候不要输入密码**

### deploy

最后的 `workflow` 文件里面的 `npm hexo deploy` 是需要把项目根目录的 `_config.yml` 文件里面的 `deploy` type 修改成这样：

``` yaml
deploy:
  type: 'git'
  repo: "git@github.com:champly/champly.github.io.git"
  branch: main
  name: champly
  email: champly@outlook.com
```

同时还需要安装 `hexo-deployer-git`，要不然的话是不支持 `git` 类型，使用 `npm install hexo-deployer-git` 进行安装

### themes config

[_config.theme.yml](https://github.com/champly/champly.github.io/blob/source/_config.theme.yml) 这里面是我的配置，在 [workflow](https://github.com/champly/champly.github.io/blob/source/.github/workflows/deploy.yml) 里面是有一个替换配置和导入 `images` 的过程

``` yaml
cp _config.theme.yml themes/keep/_config.yml
cp images/* themes/keep/source/images/
```

这里的主要逻辑就是通过 `github actions` 自动构建，然后通过配置证书，让 `npm deploy` 的时候可以直接推送到 `main` 分支，所以就需要把默认分支配置成 `source`，展示的分支配置成 `main`.

其他的部分在上面的文档里面介绍的比较详细了，可以多看看.
