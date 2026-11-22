<?php
const CS_CHAIN='CROWDSEC_CHAIN';
const SETTINGS_SCHEMA=46;
const BUILTIN=['raw'=>['PREROUTING','OUTPUT'],'mangle'=>['PREROUTING','INPUT','FORWARD','OUTPUT','POSTROUTING'],'filter'=>['INPUT','FORWARD','OUTPUT'],'nat'=>['PREROUTING','INPUT','OUTPUT','POSTROUTING']];
function alias_map($s){return ['ports'=>[]];}
function list_sets($s){return [];}
function fq_parse($s){return [];}
require dirname(__DIR__) . '/modules/02_rule_model.php';
require dirname(__DIR__) . '/modules/03_rule_generation.php';
require dirname(__DIR__) . '/modules/15_apps_services.php';
