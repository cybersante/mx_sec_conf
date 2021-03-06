local monitoring_hosts = rspamd_config:add_map{
  url = "/etc/rspamd/custom/monitoring_nolog.map",
  description = "Monitoring hosts",
  type = "regexp"
}

rspamd_config:register_symbol({
  name = 'KEEP_SPAM',
  type = 'prefilter',
  callback = function(task)
    local util = require("rspamd_util")
    local rspamd_logger = require "rspamd_logger"
    local rspamd_ip = require 'rspamd_ip'
    local uname = task:get_user()

    if uname then
      return false
    end

    local redis_params = rspamd_parse_redis_server('keep_spam')
    local ip = task:get_from_ip()

    if ip == nil or not ip:is_valid() then
      return false
    end

    local from_ip_string = tostring(ip)
    ip_check_table = {from_ip_string}

    local maxbits = 128
    local minbits = 32
    if ip:get_version() == 4 then
        maxbits = 32
        minbits = 8
    end
    for i=maxbits,minbits,-1 do
      local nip = ip:apply_mask(i):to_string() .. "/" .. i
      table.insert(ip_check_table, nip)
    end
    local function keep_spam_cb(err, data)
      if err then
        rspamd_logger.infox(rspamd_config, "keep_spam query request for ip %s returned invalid or empty data (\"%s\") or error (\"%s\")", ip, data, err)
        return false
      else
        for k,v in pairs(data) do
          if (v and v ~= userdata and v == '1') then
            rspamd_logger.infox(rspamd_config, "found ip in keep_spam map, setting pre-result", v)
            task:set_pre_result('accept', 'IP matched with forward hosts')
          end
        end
      end
    end
    table.insert(ip_check_table, 1, 'KEEP_SPAM')
    local redis_ret_user = rspamd_redis_make_request(task,
      redis_params, -- connect params
      'KEEP_SPAM', -- hash key
      false, -- is write
      keep_spam_cb, --callback
      'HMGET', -- command
      ip_check_table -- arguments
    )
    if not redis_ret_user then
      rspamd_logger.infox(rspamd_config, "cannot check keep_spam redis map")
    end
  end,
  priority = 19
})

rspamd_config:register_symbol({
  name = 'TLS_HEADER',
  type = 'postfilter',
  callback = function(task)
    local rspamd_logger = require "rspamd_logger"
    local tls_tag = task:get_request_header('TLS-Version')
    if type(tls_tag) == 'nil' then
      task:set_milter_reply({
        add_headers = {['X-Last-TLS-Session-Version'] = 'None'}
      })
    else
      task:set_milter_reply({
        add_headers = {['X-Last-TLS-Session-Version'] = tostring(tls_tag)}
      })
    end
  end,
  priority = 12
})

rspamd_config:register_symbol({
  name = 'TAG_MOO',
  type = 'postfilter',
  callback = function(task)
    local util = require("rspamd_util")
    local rspamd_logger = require "rspamd_logger"

    local tagged_rcpt = task:get_symbol("TAGGED_RCPT")
    local mailcow_domain = task:get_symbol("RCPT_MAILCOW_DOMAIN")

    if tagged_rcpt and tagged_rcpt[1].options and mailcow_domain then
      local tag = tagged_rcpt[1].options[1]
      rspamd_logger.infox("found tag: %s", tag)
      local action = task:get_metric_action('default')
      rspamd_logger.infox("metric action now: %s", action)

      if action ~= 'no action' and action ~= 'greylist' then
        rspamd_logger.infox("skipping tag handler for action: %s", action)
        task:set_metric_action('default', action)
        return true
      end

      local wants_subject_tag = task:get_symbol("RCPT_WANTS_SUBJECT_TAG")
      local wants_subfolder_tag = task:get_symbol("RCPT_WANTS_SUBFOLDER_TAG")

      if wants_subject_tag then
        rspamd_logger.infox("user wants subject modified for tagged mail")
        local sbj = task:get_header('Subject')
        new_sbj = '=?UTF-8?B?' .. tostring(util.encode_base64('[' .. tag .. '] ' .. sbj)) .. '?='
        task:set_milter_reply({
          remove_headers = {['Subject'] = 1},
          add_headers = {['Subject'] = new_sbj}
        })
      elseif wants_subfolder_tag then
        rspamd_logger.infox("Add X-Moo-Tag header")
        task:set_milter_reply({
          add_headers = {['X-Moo-Tag'] = 'YES'}
        })
      end
    end
  end,
  priority = 11
})

rspamd_config:register_symbol({
  name = 'DYN_RL_CHECK',
  type = 'prefilter',
  callback = function(task)
    local util = require("rspamd_util")
    local redis_params = rspamd_parse_redis_server('dyn_rl')
    local rspamd_logger = require "rspamd_logger"
    local envfrom = task:get_from(1)
    local uname = task:get_user()
    if not envfrom or not uname then
      return false
    end
    local uname = uname:lower()

    local env_from_domain = envfrom[1].domain:lower() -- get smtp from domain in lower case

    local function redis_cb_user(err, data)

      if err or type(data) ~= 'string' then
        rspamd_logger.infox(rspamd_config, "dynamic ratelimit request for user %s returned invalid or empty data (\"%s\") or error (\"%s\") - trying dynamic ratelimit for domain...", uname, data, err)

        local function redis_key_cb_domain(err, data)
          if err or type(data) ~= 'string' then
            rspamd_logger.infox(rspamd_config, "dynamic ratelimit request for domain %s returned invalid or empty data (\"%s\") or error (\"%s\")", env_from_domain, data, err)
          else
            rspamd_logger.infox(rspamd_config, "found dynamic ratelimit in redis for domain %s with value %s", env_from_domain, data)
            task:insert_result('DYN_RL', 0.0, data, env_from_domain)
          end
        end

        local redis_ret_domain = rspamd_redis_make_request(task,
          redis_params, -- connect params
          env_from_domain, -- hash key
          false, -- is write
          redis_key_cb_domain, --callback
          'HGET', -- command
          {'RL_VALUE', env_from_domain} -- arguments
        )
        if not redis_ret_domain then
          rspamd_logger.infox(rspamd_config, "cannot make request to load ratelimit for domain")
        end
      else
        rspamd_logger.infox(rspamd_config, "found dynamic ratelimit in redis for user %s with value %s", uname, data)
        task:insert_result('DYN_RL', 0.0, data, uname)
      end

    end

    local redis_ret_user = rspamd_redis_make_request(task,
      redis_params, -- connect params
      uname, -- hash key
      false, -- is write
      redis_cb_user, --callback
      'HGET', -- command
      {'RL_VALUE', uname} -- arguments
    )
    if not redis_ret_user then
      rspamd_logger.infox(rspamd_config, "cannot make request to load ratelimit for user")
    end
    return true
  end,
  flags = 'empty',
  priority = 20
})

rspamd_config:register_symbol({
  name = 'NO_LOG_STAT',
  type = 'postfilter',
  callback = function(task)
    local from = task:get_header('From')
    if from and monitoring_hosts:get_key(from) then
      task:set_flag('no_log')
      task:set_flag('no_stat')
    end
  end
})
rspamd_config.HTML_WITH_FORM = {
  callback = function(task)
    local tp = task:get_text_parts()
    if (not tp) then return false end
    for _,p in ipairs(tp) do
      if p:is_html() then
        local hc = p:get_html()
        if (not hc) then return false end
        if (hc:has_tag('form')) then return true end
      end
    end
    return false
  end,
  description = 'HTML with form',
  score = 10.0,
  group = 'html'
}

config['regexp']['BODY_CONTAINS_PASSWORD'] = {
    re = '/mot de passe|password|passwd/i{words}',
    score = 0.1,
    description = 'password or mot de passe in words from body'
}
config['regexp']['PHISHING_WORDS_ID'] = {
    re = '/mot de passe|password|utilisate|user|login|passwd|identif|credential/i{words}',
    score = 0.0,
    description = 'password or mot de passe in words from body'
}
config['regexp']['PHISHING_WORDS_MSG'] = {
    re = '/securit|quota|reinit|full|plein|illegal|support|admin|helpdesk/i{words}',
    score = 0.0,
    description = 'password or mot de passe in words from body'
}

local check_from_display_name_suspect = rspamd_config:register_symbol{
  type = 'callback,mime',
  name = 'FROM_DISPLAYS_CALLBACK',
  callback = function (task)
    local from = task:get_from(2)
    if not (from and from[1] and from[1].name and from[1].user) then return false end
    if (from[1].name == "" or from[1].user == "") then return false end
    local dispname = string.gsub(from[1].name, "%s+", "")
    if dispname == "" then return false end
    -- See if we can parse an email address from the name
    -- "false name" <real.name@dom.com> => from[1].name == "false name" || from[1].user == "real.name"
    -- split name ( blank and dot) and search (lowcase) in user
    local found = false
    local cnt_b = 0
    for i in string.gmatch(from[1].name, "%S+") do
	cnt_b = cnt_b + 1
        if  string.find(string.lower(from[1].user), string.lower(i)) then
            found = true
        end
        if found then return false end
    end
    local cnt_p = 0
    for i in string.gmatch(from[1].name, "%.") do
	cnt_p = cnt_p + 1
        if  string.find(string.lower(from[1].user), string.lower(i)) then
            found = true
        end
        if found then return false end
    end
    if not (cnt_p == 2 or cnt_b == 2 or cnt_b == 3 or cnt_p == 3) then return false end
    if not found then
      task:insert_result('SUSPECT_DISPLAY_NAME', 1.0, from[1]['name'], from[1]['user'])
      return false
    end
    return false
  end,
  group = 'headers',
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = check_from_display_name_suspect,
  name = 'SUSPECT_DISPLAY_NAME',
  description = 'Display name use suspect information, potential spoof',
  group = 'headers',
  score = 2.0,
}

local check_xoip_suspect = rspamd_config:register_symbol{
  type = 'callback,mime',
  name = 'SUSPECT_XOIP_CALLBACK',
  callback = function (task)
    local rspamd_logger = require "rspamd_logger"
    local rspamd_regexp = require "rspamd_regexp"
    local origin = task:get_header('X-Originating-IP')
    if origin then
      origin = string.sub(origin, 2, -2)
      local rspamd_ip = require "rspamd_ip"
      local test = rspamd_ip.from_string(origin)
      if test and test:is_valid() and not test:is_local() then
        local dnsbl = 'asn.rspamd.com'
        local req_name = string.format("%s.%s", table.concat(test:inversed_str_octets(), '.'), dnsbl)
        -- check geoip
        local country = nil
	local function rspamd_dns_geo(resolver, to_resolve, results, dns_err, _, serv)
          local rspamd_re = rspamd_regexp.create_cached("[\\|\\s]")
          if dns_err and (dns_err ~= 'requested record is not found' and dns_err ~= 'no records with this name') then
            rspamd_logger.errx(task, 'error querying dns "%s" on %s: %s', req_name, serv, dns_err)
            return
          end
          if not (results and results[1]) then
            rspamd_logger.infox(task, 'cannot query ip %s on %s: no results', req_name, serv)
            return
          end
          -- rspamd_logger.errx(task, 'querying dns "%s" on %s => %s', req_name, serv, results[1])
          local parts = rspamd_re:split(results[1])
          if parts and parts[3] then
            country = parts[3]
          end
          if country then
            local found = false
            local parts = task:get_text_parts()
            for _, p in ipairs(parts) do
              local langs = p:get_languages()
              if langs then
                local l = nil
                local best = -10,01
                for key,col in pairs(langs) do 
                --for l in langs do
                  --rspamd_logger.errx(task, 'DEBUG lang detect: k=%s v=%s', key, col)
                  if col and col['code'] and col['prob'] and col['prob'] > best then
                    --rspamd_logger.errx(task, 'DEBUG lang detect CHOICE: k=%s v=%s', key, col)
                    best = col['prob']
                    l = col['code']
                  end
                end
                -- rspamd_logger.errx(task, 'Select lang detect: %s', l)
                if l and string.lower(l) == string.lower(country) then
                    found = true
                    -- rspamd_logger.errx(task, 'DEBUG found 1: %s == %s', l, country)
                    return false
                end
              end
            end
            local from = task:get_from(2)
            if (from and from[1] and from[1].domain) then
              local tld = nil
              for x in string.gmatch(from[1].domain, "[^%.]+") do
                  tld = x
              end
              if tld then
                --rspamd_logger.errx(task, 'DEBUG country dom: %s', tld)
                if (string.lower(tld) == string.lower(country)) then
                 --rspamd_logger.errx(task, 'DEBUG found same country: %s == %s', tld, country)
                 found = true
                 return false
                end
              end
            end
            if not found then
              task:insert_result('SUSPECT_XOIP', 1.0, country)
              return false
            end
          end
          return
        end
        task:get_resolver():resolve_txt({task = task, name = req_name, callback = rspamd_dns_geo})
      end
    end
    return false
  end,
  group = 'headers',
}

rspamd_config:register_symbol{
  type = 'virtual',
  parent = check_xoip_suspect ,
  name = 'SUSPECT_XOIP',
  description = 'X-Origine IP suspect (potential account compromised)',
  group = 'headers',
  score = 4.0,
}

