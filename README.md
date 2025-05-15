# Go 模板项目

本项目是一个使用 GitHub Actions 实现自动化流程的 Go 服务模板，包含以下功能：
- Golint 代码静态检查
- Sonar 代码质量检测
- 单元测试覆盖率统计
- Docker 镜像打包
- 部署到远程 K8s 集群

## 项目结构
```
. 
├── .github 
│   └── workflows 
│       └── go-ci.yml 
├── k8s 
│   ├── deployment.yaml 
│   └── service.yaml 
├── Dockerfile 
├── main.go 
└── README.md 
```

## 配置步骤
### 1. 配置 GitHub Secrets
在 GitHub 仓库的 `Settings` -> `Secrets` -> `Actions` 中添加以下 secrets：
- `SONAR_TOKEN`: SonarQube 访问令牌。
- `SONAR_HOST_URL`: SonarQube 服务器地址。
- `KUBE_CONFIG_DATA`: K8s 集群配置文件的 Base64 编码。

### 2. 自定义 Docker 镜像标签
在 `.github/workflows/go-ci.yml` 文件中，修改 `docker-build` job 的 `tags` 参数，将 `user/app:latest` 替换为你自己的镜像标签。

### 3. 自定义 K8s 部署文件
在 `k8s` 目录下，根据实际需求修改 `deployment.yaml` 和 `service.yaml` 文件。

## 使用方法
### 开发环境
1. 克隆仓库：
```bash
 git clone <your-repo-url> 
 cd <your-repo-name> 
```
2. 运行 Go 服务：
```bash
 go run main.go 
```

### 生产环境
当代码推送到 `main` 分支或提交 `main` 分支的 Pull Request 时，GitHub Actions 会自动触发以下流程：
1. 执行 Golint 代码静态检查。
2. 执行 Sonar 代码质量检测。
3. 运行单元测试并生成覆盖率报告。
4. 构建 Docker 镜像。
5. 部署到远程 K8s 集群。

## 注意事项
- 确保 SonarQube 服务器和 K8s 集群正常运行。
- 定期更新 GitHub Actions 配置文件中的依赖版本。
- 确保 Docker 镜像仓库有足够的存储空间。