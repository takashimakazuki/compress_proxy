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

#ifndef DOCA_UTILS_H_
#define DOCA_UTILS_H_

#include <doca_error.h>
#include <doca_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PCI_ADDR_SIZE 8 /* Null terminator included */

/**
 * @brief Parse a PCI address string into a doca_bdf struct
 *
 * @param [in] pci_addr
 * The PCI address string
 * @param [out] bdf
 * The doca_bdf struct with the PCI address parameters
 *
 * @return
 * DOCA_SUCCESS - in case of success.
 * doca_error code - in case of failure:
 * - DOCA_ERROR_INVALID_VALUE - if an invalid input had been received.
 */
doca_error_t doca_pci_bdf_from_string(const char *pci_addr, struct doca_pci_bdf *bdf);

/**
 * @brief Generate a pci address string from a doca_bdf struct
 *
 * @param [in] bdf
 * The doca_bdf struct
 * @param [out] pci_addr
 * The generated PCI address string (see size requirement below)
 * @param [in] buf_size
 * The size of the buffer pci_addr, must be at least PCI_ADDR_SIZE
 *
 * @return
 * DOCA_SUCCESS - in case of success.
 * doca_error code - in case of failure:
 * - DOCA_ERROR_INVALID_VALUE - if an invalid input had been received.
 */
doca_error_t doca_pci_bdf_to_string(const struct doca_pci_bdf *bdf, char *pci_addr, size_t buf_size);

#ifdef __cplusplus
}
#endif

#endif /* DOCA_UTILS_H_ */
