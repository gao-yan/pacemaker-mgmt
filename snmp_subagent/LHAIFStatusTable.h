/*
 * Note: this file originally auto-generated by mib2c using
 *        : mib2c.iterate.conf,v 5.9 2003/06/04 00:14:41 hardaker Exp $
 */
#ifndef LHAIFSTATUSTABLE_H
#define LHAIFSTATUSTABLE_H

/* function declarations */
void init_LHAIFStatusTable(void);
void initialize_table_LHAIFStatusTable(void);
Netsnmp_Node_Handler LHAIFStatusTable_handler;

Netsnmp_First_Data_Point  LHAIFStatusTable_get_first_data_point;
Netsnmp_Next_Data_Point   LHAIFStatusTable_get_next_data_point;

/* column number definitions for table LHAIFStatusTable */
#include "LHAIFStatusTable_columns.h"

/* enum definions */
#include "LHAIFStatusTable_enums.h"

#endif /* LHAIFSTATUSTABLE_H */