REGISTRY = local-registry:5000
IMAGE = seccomp-agent
TAG = latest
IMAGE_FULL = $(REGISTRY)/$(IMAGE):$(TAG)

.PHONY: build-agent push-agent build-push-agent start-registry stop-registry

build-agent:
	docker build -t $(IMAGE_FULL) .

push-agent:
	docker push $(IMAGE_FULL)

build-push-agent: build-agent push-agent

deploy: build-push-agent start-registry 
	kind delete cluster || true
	kind create cluster --config=kind-config.yaml
	kubectl apply -f seccomp-agent.yaml
	kubectl apply -f test-pod.yaml

roll-agent: build-push-agent
	kubectl rollout restart daemonset/seccomp-agent -nseccomp-agent

start-registry:
	docker run -d -p 5000:5000 --network kind --name local-registry registry:2 

stop-registry:
	docker stop local-registry && docker rm local-registry

clean:
	rm -f seccomp-agent
	go clean -modcache
	-docker rm -f local-registry
	-docker rmi $(IMAGE_FULL)
