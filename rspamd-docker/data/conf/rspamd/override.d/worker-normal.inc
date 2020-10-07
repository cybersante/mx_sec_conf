bind_socket = "*:11333";
task_timeout = 30s;
dns_max_requests = 100;
count = 1;
.include(try=true; priority=20) "$CONFDIR/override.d/worker-normal.custom.inc"
