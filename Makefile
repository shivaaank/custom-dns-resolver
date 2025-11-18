# ----------------------------------------
# Custom DNS Resolver Makefile
# Option 1: Disable systemd-resolved so we can bind to port 53
# ----------------------------------------

RESOLVER_IP = 127.0.0.1
STATE_FILE = .dns_state

.PHONY: enable disable clean run show


# ------------------------------------------------------------
# enable: disable systemd-resolved + set /etc/resolv.conf
# ------------------------------------------------------------
enable:
	@if [ -f $(STATE_FILE) ]; then \
		echo "[ERROR] DNS resolver already enabled. Run 'make disable' first."; \
		exit 1; \
	fi

	@echo "[INFO] Saving current DNS state..."
	@echo "=== systemctl status systemd-resolved ===" > $(STATE_FILE)
	@systemctl is-enabled systemd-resolved >> $(STATE_FILE)
	@echo "=== /etc/resolv.conf ===" >> $(STATE_FILE)
	@cp /etc/resolv.conf resolv.conf.backup
	@echo "BACKUP: resolv.conf.backup" >> $(STATE_FILE)

	@echo "[INFO] Stopping systemd-resolved..."
	@sudo systemctl stop systemd-resolved

	@echo "[INFO] Disabling systemd-resolved..."
	@sudo systemctl disable systemd-resolved

	@echo "[INFO] Replacing /etc/resolv.conf with localhost DNS"
	@sudo rm -f /etc/resolv.conf
	@echo "nameserver $(RESOLVER_IP)" | sudo tee /etc/resolv.conf >/dev/null

	@echo "[SUCCESS] System now using custom DNS resolver on 127.0.0.1."
	@echo "Run: sudo python3 resolver.py"


# ------------------------------------------------------------
# disable / clean: restore systemd-resolved + resolv.conf
# ------------------------------------------------------------
disable clean:
	@if [ ! -f $(STATE_FILE) ]; then \
		echo "[WARN] No DNS state file. Nothing to restore."; \
		exit 0; \
	fi

	@echo "[INFO] Restoring systemd-resolved..."
	@sudo systemctl enable systemd-resolved
	@sudo systemctl start systemd-resolved

	@echo "[INFO] Restoring /etc/resolv.conf..."
	@sudo rm -f /etc/resolv.conf
	@sudo cp resolv.conf.backup /etc/resolv.conf

	@echo "[INFO] Cleaning up..."
	@rm -f $(STATE_FILE)
	@rm -f resolv.conf.backup

	@echo "[SUCCESS] DNS restored. System back to normal."


# ------------------------------------------------------------
# run: start resolver
# ------------------------------------------------------------
run:
	sudo python3 resolver.py

# ------------------------------------------------------------
# show: show current DNS settings
# ------------------------------------------------------------
show:
	@cat /etc/resolv.conf
