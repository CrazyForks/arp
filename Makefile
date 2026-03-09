.PHONY: all server client clean test clippy fmt release deploy-server

RELEASE_DIR := releases/latest
DEPLOY_DIR ?= /opt/arp

all: test clippy server client

test:
	cargo test --workspace

clippy:
	cargo clippy --workspace --all-targets -- -D warnings


fmt:
	cargo fmt --all

server:
	cargo zigbuild --release -p arps --target x86_64-unknown-linux-gnu

client:
	cargo zigbuild --release -p arpc --target x86_64-unknown-linux-gnu
	cargo zigbuild --release -p arpc --target aarch64-unknown-linux-gnu

release: test clippy server client
	mkdir -p $(RELEASE_DIR)
	cp target/x86_64-unknown-linux-gnu/release/arps $(RELEASE_DIR)/arps-linux-x86_64
	cp target/x86_64-unknown-linux-gnu/release/arpc $(RELEASE_DIR)/arpc-linux-x86_64
	cp target/aarch64-unknown-linux-gnu/release/arpc $(RELEASE_DIR)/arpc-linux-aarch64
	@echo ""
	@echo "Release binaries:"
	@ls -lh $(RELEASE_DIR)/
	@echo ""
	@echo "Note: macOS binaries require building on macOS or via CI with macOS SDK."

deploy-server: server
	@echo 'Backing up current binary...'
	-sudo cp $(DEPLOY_DIR)/arps $(DEPLOY_DIR)/arps.bak
	sudo systemctl stop arps
	sudo cp target/x86_64-unknown-linux-gnu/release/arps $(DEPLOY_DIR)/arps
	if sudo systemctl start arps && sleep 2 && systemctl is-active --quiet arps; then \
		echo 'Deploy successful'; \
	else \
		echo 'Deploy FAILED — rolling back...'; \
		sudo systemctl stop arps || true; \
		if [ -f $(DEPLOY_DIR)/arps.bak ]; then \
			sudo cp $(DEPLOY_DIR)/arps.bak $(DEPLOY_DIR)/arps; \
			sudo systemctl start arps; \
			echo 'Rolled back to previous version'; \
		else \
			echo 'ERROR: No backup available for rollback!'; \
			exit 1; \
		fi; \
		exit 1; \
	fi

clean:
	cargo clean
