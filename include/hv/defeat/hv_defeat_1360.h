#ifndef HV_DEFEAT_1360_H
#define HV_DEFEAT_1360_H

/*
 * High-firmware (8.xx+) hypervisor defeat, 13.60 port of the Byepervisor khook
 * escape. See source/hv/defeat/hv_defeat_1360.c for the design.
 */
int hv_defeat_1360(void);

/*
 * Second phase, run after waking from rest mode (once break_hv has disabled
 * NPT): take over the hypervisor from the BSP and boot Linux. Does not return.
 */
int hv_defeat_1360_post_resume(void);

#endif
