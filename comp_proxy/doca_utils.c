/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <doca_log.h>

#include "doca_utils.h"

DOCA_LOG_REGISTER(DOCA_UTILS);

doca_error_t
doca_pci_bdf_from_string(const char *pci_addr, struct doca_pci_bdf *bdf)
{
	if (pci_addr == NULL || bdf == NULL) {
		DOCA_LOG_ERR("Unable to parse pci bdf from string: Received invalid input: pci_addr=%p, bdf=%p",
			     pci_addr, bdf);
		return DOCA_ERROR_INVALID_VALUE;
	}

	if (strlen(pci_addr) != PCI_ADDR_SIZE - 1 || pci_addr[2] != ':' || pci_addr[5] != '.') {
		DOCA_LOG_ERR("Unable to parse pci bdf from string: Input doesn't meet the pci address convention: XX:XX.X");
		return DOCA_ERROR_INVALID_VALUE;
	}

	char *endptr;
	uint32_t bus, device, function;
	char tmp_str[4];

	tmp_str[0] = pci_addr[0];
	tmp_str[1] = pci_addr[1];
	tmp_str[2] = '\0';

	errno = 0;
	bus = strtoul(tmp_str, &endptr, 16);
	if (errno != 0 || endptr != (tmp_str + 2) || bus >= PCI_BUS_MAX_VALUE) {
		DOCA_LOG_ERR("Unable to parse pci bdf from string: Failed to parse the bus value");
		return DOCA_ERROR_INVALID_VALUE;
	}

	tmp_str[0] = pci_addr[3];
	tmp_str[1] = pci_addr[4];
	tmp_str[2] = '\0';

	device = strtoul(tmp_str, &endptr, 16);
	if (errno != 0 || endptr != (tmp_str + 2) || device >= PCI_DEVICE_MAX_VALUE) {
		DOCA_LOG_ERR("Unable to parse pci bdf from string: Failed to parse the device value");
		return DOCA_ERROR_INVALID_VALUE;
	}

	tmp_str[0] = pci_addr[6];
	tmp_str[1] = '\0';

	function = strtoul(tmp_str, &endptr, 16);
	if (errno != 0 || endptr != (tmp_str + 1) || function >= PCI_FUNCTION_MAX_VALUE) {
		DOCA_LOG_ERR("Unable to parse pci bdf from string: Failed to parse the function value");
		return DOCA_ERROR_INVALID_VALUE;
	}

	bdf->bus = bus;
	bdf->device = device;
	bdf->function = function;

	return DOCA_SUCCESS;
}

doca_error_t
doca_pci_bdf_to_string(const struct doca_pci_bdf *bdf, char *pci_addr, size_t buf_size)
{
	if (bdf == NULL || pci_addr == NULL || buf_size < PCI_ADDR_SIZE) {
		DOCA_LOG_ERR("Unable to generate pci address from pci bdf struct: Received invalid input: bdf=%p, pci_add=%p, buf_size=%zu",
			bdf, pci_addr, buf_size);
		return DOCA_ERROR_INVALID_VALUE;
	}

	if (snprintf(pci_addr, PCI_ADDR_SIZE, "%02x:%02x.%u", bdf->bus, bdf->device, bdf->function) < 0) {
		DOCA_LOG_ERR("Unable to generate pci address from pci bdf struct: Failed to write to buffer");
		return DOCA_ERROR_INVALID_VALUE;
	}

	pci_addr[PCI_ADDR_SIZE - 1] = '\0';

	return DOCA_SUCCESS;
}
