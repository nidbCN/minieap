#include "config.h"
#include "if_impl.h"
#include "packet_plugin.h"
#include "packet_builder.h"
#include "logging.h"
#include "eap_state_machine.h"
#include "sched_alarm.h"
#include "misc.h"
#include "conf_parser.h"
#include "pid_lock.h"

#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>

#ifdef __linux__
#include <linux/if_ether.h>
#else
#define ETH_P_PAE 0x888e
#endif

/*
 * Initialize the settings.
 * Note: Override values in config file with cmdline.
 */
static int init_program_config(int argc, char* argv[]) {
    PROG_CONFIG* cfg;

    load_default_params();
    if (IS_FAIL(parse_cmdline_conf_file(argc, argv))) {
        PR_ERR("An error occurred when parse config file path");
        goto err;
    }

    cfg = get_program_config();
    if (IS_FAIL(parse_config_file(cfg->conffile))) {
        PR_WARN("Can not parse config file, please check your command");
    }
    if (IS_FAIL(parse_cmdline_opts(argc, argv))) {
        PR_ERR("An error occurred when parse command line arguments");
        goto err;
    }

    return validate_params();
err:
    return FAILURE;
}

/*
 * Initialize the settings. Called after plugins being selected.
 * Note: Override values in config file with cmdline.
 */
static int init_plugin_config(int argc, char* argv[]) {
    PROG_CONFIG *cfg = get_program_config();

    packet_plugin_load_default_params();
    if (IS_FAIL(packet_plugin_process_config_file(cfg->conffile))) {
        PR_ERR("An error occurred when parse config file of plugin");
        goto err;
    }
    if (IS_FAIL(packet_plugin_process_cmdline_opts(argc, argv))) {
        PR_ERR("An error occurred when parse command line arguments of plugin");
        goto err;
    }
    return packet_plugin_validate_params();
err:
    return FAILURE;
}

static void packet_plugin_list_select(void* name, void* unused) {
    if (IS_FAIL(select_packet_plugin((const char*)name))) {
        PR_WARN("Plugin %s not found, please check", name);
    }
}

/*
 * Do all the initialization tasks
 */
static int init_cfg(int argc, char* argv[]) {
    PROG_CONFIG* cfg = get_program_config();

    /* Temporaory logs */
    set_log_destination(LOG_TO_CONSOLE);
    start_log();

    init_if_impl_list();
    init_packet_plugin_list();

    PR_RAW("MiniEAP " VERSION "\n"
           "Hamster Tian, 2016\n\n");

    PR_RAW("Traslated by Gaein nidb");

    if (IS_FAIL(init_program_config(argc, argv))) {
        PR_ERR("Program init failed");
        return FAILURE;
    }

    list_traverse(cfg->packet_plugin_list, packet_plugin_list_select, NULL);

    if (IS_FAIL(select_if_impl(cfg->if_impl))) {
        PR_ERR("Network plugin start failed, please check name spell");
        return FAILURE;
    }

    packet_plugin_print_banner();

    if (IS_FAIL(init_plugin_config(argc, argv))) {
        PR_ERR("Plugin init failed");
        return FAILURE;
    }

    if (cfg->save_now) {
        save_config_file();
    }

    /* Parsed in parse_config_file(). This is no longer needed */
    conf_parser_free();

    if (IS_FAIL(pid_lock_init(cfg->pidfile))) {
        return FAILURE;
    }

    return SUCCESS;
}

static int init_if() {
    PROG_CONFIG* cfg = get_program_config();
    IF_IMPL* if_impl;

    if_impl = get_if_impl();
    if (IS_FAIL(if_impl->set_ifname(if_impl,cfg->ifname))) {
        PR_ERR("Setup interface name failed");
        return FAILURE;
    }

    if (IS_FAIL(if_impl->setup_capture_params(if_impl, ETH_P_PAE, FALSE))) {
        PR_ERR("Setup capture params failed");
        return FAILURE;
    }

    if (IS_FAIL(if_impl->prepare_interface(if_impl))) {
        PR_ERR("Prepare interface failed");
        return FAILURE;
    }

    if_impl->set_frame_handler(if_impl, eap_state_machine_recv_handler);

    return SUCCESS;
}

static void apply_log_daemon_params() {
    PROG_CONFIG* cfg = get_program_config();

    if (cfg->daemon_type != DAEMON_FOREGROUND) {
        PR_INFO("Try running background...");
        if (IS_FAIL(go_background())) {
            PR_WARN("Can not running background");
        }
    }

    /* Apply log destination */
    close_log();
    start_log();
}

static void exit_handler() {
    free_if_impl();
    packet_plugin_destroy();
    eap_state_machine_destroy();
    sched_alarm_destroy();
    pid_lock_destroy();
    free_config();
    PR_INFO("MiniEAP Exited");
    close_log();
}

static void signal_handler(int signal) {
    exit(0);
}

/*
 * Detailed errors are printed where they happen, not here ...
 */
int main(int argc, char* argv[]) {
    srand(time(0));
    atexit(exit_handler);
	signal(SIGHUP, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

    if (IS_FAIL(init_cfg(argc, argv))) {
        return FAILURE;
    }

    if (IS_FAIL(init_if())) {
        return FAILURE;
    }

    if (IS_FAIL(eap_state_machine_init())) {
        return FAILURE;
    }

    if (IS_FAIL(sched_alarm_init())) {
        return FAILURE;
    }

    if (IS_FAIL(pid_lock_lock())) {
        return FAILURE;
    }

    apply_log_daemon_params();

    pid_lock_save_pid();

    switch_to_state(EAP_STATE_PREPARING, NULL);

    return 0;
}
