const express = require('express')
const fs = require('fs');


const bodyParser = require('body-parser');
const { request } = require('http');
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

app.use(express.static('public'));

const AUTH_KEY = "abc123DEF";

getClamSignature = 
[
    {
        "name": "logical-signature",
        "content": "Sig1;Target:0;(0&1&2&3)&(4|1);6b6f74656b;616c61;7a6f6c77;73746566616e;deadbeef",
        "type": "ldb"
   
    },
    {
        "name": "info-signature",
        "content": "name:size:sha256",
        "type": "info"
   
    }
]

const helloMsg = "Wellcome to test Manager IPS"

const attAppLinux =  ['description', 'application_name', 'architect', 'version']

const attAppWin = ["name", "url", "rate", "star", "version", "cve_list_version"]

const attFireWall  = ["Rule Name", "Direction", "LocalIP", "RemoteIP", "LocalPort", "RemotePort", "Action"]

const chechService = [ "time", "name", "type", "content"]

const virusScanAtt = ["path", "time"]


const resAppLinux  =[
    {
        "description": "Display graphical dialog boxes from shell scripts (common files)",
        "application_name": "zenity-common",
        "architect": "all",
        "version": "3.18.1.1-1ubuntu2"
    },
    {
        "description": "Archiver for .zip files",
        "application_name": "zip",
        "architect": "amd64",
        "version": "3.0-11"
    },
    {
        "description": "compression library - runtime",
        "application_name": "zlib1g:amd64",
        "architect": "amd64",
        "version": "1:1.2.8.dfsg-2ubuntu4.3"
    }
]

const resAppWin = [
    {
        "name": "Mozilla Firefox",
        "url": "https://www.mozilla.org/vi/firefox/new/",
        "rate": "4.2 stars out of 5 with 1,879 ratings",
        "star": "4.2",
        "version": "7.3",
        "cve_list_version": "https://www.cvedetails.com/version-list/452/3264/1/Mozilla-Firefox.html"
    },
    {
        "name": "Google Chrome",
        "url": "https://www.google.com/chrome/?brand=CHBD&gclid=CjwKCAjwguzzBRBiEiwAgU0FT59wlC8j_2OQjqTlHKMa9JlBJ0XcjQ_YNddaoqMKbKdYksSJ4PIO4xoCbPoQAvD_BwE&gclsrc=aw.ds",
        "rate": "3.8 stars out of 5 with 169 ratings",
        "star": "3.8",
        "version": "80.0.3987.149",
        "cve_list_version": "https://www.cvedetails.com/version-list/1224/15031/1/Google-Chrome.html"
    }
]

const resFirewall = [
    {
        "Rule Name": "TEST1",
        "Direction": "In",
        "LocalIP": "1.2.3.4",
        "RemoteIP": "127.0.0.1",
        "LocalPort": "80",
        "RemotePort": "Any",
        "Action": "Block"
    },
    {
        "Rule Name": "TEST1",
        "Direction": "Out",
        "LocalIP": "Any",
        "RemoteIP": "8.8.8.8",
        "LocalPort": "Any",
        "RemotePort": "Any",
        "Action": "Block"
    }
]

const ruleModPc = [
    {
      "bkcsPC": ["trustware","dga"],
      "PC1": ["dga"],
      "PC2": ["custom"]
    }
]

const ruleClamPc = [
    {
      "bkcsPC": ["clamrule1"],
      "PC1": ["dga"],
      "PC2": ["custom"]
    }
]

const modRule = [
    {
        "Rule Name": "TEST1",
        "Direction": "In",
        "LocalIP": "1.2.3.4",
        "RemoteIP": "127.0.0.1",
        "LocalPort": "80",
        "RemotePort": "Any",
        "Action": "Block"
    },
    {
        "Rule Name": "TEST1",
        "Direction": "Out",
        "LocalIP": "Any",
        "RemoteIP": "8.8.8.8",
        "LocalPort": "Any",
        "RemotePort": "Any",
        "Action": "Block"
    }
]


const MSG_AUTH_EROR = "Authentication error!";
const MSG_NO_DATA = "No data"
app.get('/', (req, res) => {
  res.send(helloMsg)
});

function checkPostReq(reqBody){
    // console.log(reqBody)
    if ('key' in reqBody == false || reqBody['key'] != AUTH_KEY){
        return MSG_AUTH_EROR;
    }else if ('data' in reqBody == false){
        return MSG_NO_DATA;
    }
    return true;

}

app.post('/get/tool/clam_signature', (req, res)=>{
    inf = req.body;
    if ('key' in inf == false || inf['key'] != AUTH_KEY){
        res.status(404).send(MSG_AUTH_EROR);
    }else{
        res.json(getClamSignature);
    }
});


app.post('/get/update_app_linux',(req, res)=>{
    inf = req.body;
    if ('key' in inf == false || inf['key'] != AUTH_KEY){
        res.status(404).send(MSG_AUTH_EROR);
    }else{
        res.json(resAppLinux);
    }
});

app.post('/get/update_mod_reulr',(req, res)=>{
    inf = req.body;
    if ('key' in inf == false || inf['key'] != AUTH_KEY){
        res.status(404).send(MSG_AUTH_EROR);
    }else{
        res.json(modRule);
    }
});

app.post('/get/modlist',(req, res)=>{
    inf = req.body;
    if ('key' in inf == false || inf['key'] != AUTH_KEY){
        res.status(404).send(MSG_AUTH_EROR);
    }else{
        res.json(ruleModPc);
    }
});

app.post('/get/clamlist',(req, res)=>{
    inf = req.body
    if ('key' in inf == false || inf['key'] != AUTH_KEY){
        res.status(404).send(MSG_AUTH_EROR)
    }else{
        res.json(ruleClamPc)
    }
});

app.post('/update_app_linux',(req, res)=>{
    body = req.body;
    msg = checkPostReq(body);
    if (msg != true){
        res.status(404).send(msg);
        return;
    }

    listApp = body['data'];
    var ssNum =0;
    var totalNum =0;
    for (i=0; i< listApp.length; i++){
        update = str[i]
        console.log(update)
        
        check = 1
        attAppLinux.forEach(att => {
            if (!(att in update)){
                check =0;
            }
        });
        ssNum += check;
        totalNum ++;
    }
    if(ssNum == totalNum){
        res.send('OK '+ ssNum + '/' + totalNum + ' apps')
    }else{
        res.status(404).send('Error parse ' +  String(totalNum - ssNum) + '/' + totalNum + ' apps')
    }
});

app.post('/get/update_app_window',(req, res)=>{
    inf = req.body;
    if ('key' in inf == false || inf['key'] != AUTH_KEY){
        res.status(404).send(MSG_AUTH_EROR);
    }else{
        res.json(resAppWin);
    }
});

app.post('/update_app_window',(req, res)=>{
    body = req.body;
    msg = checkPostReq(body);
    if (msg != true){
        res.status(404).send(msg);
        return;
    }
    
    listApp = body['data'];
    var ssNum =0;
    var totalNum =0;
    for (i=0; i< listApp.length; i++){
        update = listApp[i]
        
        check = 1
        attAppWin.forEach(att => {
            if (!(att in update)){
                check =0;
            }
        });
        ssNum += check;
        totalNum ++;
    }
    if(ssNum == totalNum){
        res.send('OK '+ ssNum + '/' + totalNum + ' apps')
    }else{
        res.status(404).send('Error parse ' + String(totalNum - ssNum) + '/' + totalNum + ' apps')
    }
});

app.post('/get/update_rule_firewall',(req, res)=>{
    inf = req.body;
    if ('key' in inf == false || inf['key'] != AUTH_KEY){
        res.status(404).send(MSG_AUTH_EROR);
    }else{
        res.json(resFirewall);
    }
})


app.post('/update_rule_firewall',(req, res)=>{
    body = req.body;
    msg = checkPostReq(body);
    if (msg != true){
        res.status(404).send(msg);
        return;
    }
    
    listRule = body['data'];
    var ssNum =0;
    var totalNum =0;
    for (i=0; i< listRule.length; i++){
        update = listRule[i]
        console.log(update)
        
        check = 1
        attFireWall.forEach(att => {
            if (!(att in update)){
                check =0;
            }
        });
        ssNum += check;
        totalNum ++;
    }
    if(ssNum == totalNum){
        res.send('OK '+ ssNum + '/' + totalNum + ' rules')
    }else{
        res.status(404).send('Error, parsed ' +  String(totalNum - ssNum)  + '/' + totalNum + ' rules')
    }
});


app.post('/checkservice',(req, res)=>{
    body = req.body;
    msg = checkPostReq(body);
    // console.log(msg)
    if (msg != true){
        res.status(404).send(msg);
        return;
    }
    
    check = JSON.parse(body['data']);
    ret = 1;
    chechService.forEach(att => {
        if(!check.hasOwnProperty(att)){
            ret = 0;
        }
    });
    if(ret == 1){
        res.send('OK')
    }else{
        res.status(404).send('Error')
    }
});

app.post('/virus-scan', (req, res)=>{
    body = req.body;
    msg = checkPostReq(body);
    if (msg != true){
        res.status(404).send(msg);
        return;
    }
    
    listRule = JSON.parse(body['data']);

    var ssNum =0;
    var totalNum =0;
    for (i=0; i< listRule.length; i++){
        update = listRule[i]
        check = 1
        virusScanAtt.forEach(att => {
            if (!(att in update)){
                check =0;
            }
        });
        ssNum += check;
        totalNum ++;
    }
    if(ssNum == totalNum){
        res.send('OK, scan '+ ssNum + '/' + totalNum)
    }else{
        res.status(404).send('Error, parsed ' +  String(totalNum - ssNum)  + '/' + totalNum)
    }
});


app.post('/moniter-update', (req, res)=>{
    body = req.body;
    msg = checkPostReq(body);
    if (msg != true){
        res.status(404).send(msg);
        return;
    }
    
    alertObj = JSON.parse(body['data']);

    if(alertObj.hasOwnProperty('alert_list')){
        alertList = alertObj['alert_list'];
        var ssNum =0;
        var totalNum =alertList.length;
        for (i=0; i< alertList.length; i++){
            updateAlert = alertList[i]
            if(updateAlert.length == 4){
                ssNum ++
            }
        }
        if(ssNum == totalNum){
            res.send('OK, scan '+ ssNum + '/' + totalNum)
        }else{
            res.status(404).send('Error, parsed ' +  String(totalNum - ssNum)  + '/' + totalNum)
        }
    }else{
        res.status(404).send("Error fomat");
    }
});

app.post('/integrity-update', (req, res)=>{
    body = req.body;
    msg = checkPostReq(body);
    if (msg != true){
        res.status(404).send(msg);
        return;
    }
    
    alertObj = JSON.parse(body['data']);
    if(alertObj.hasOwnProperty('alert_list')){
        alertList = alertObj['alert_list'];
        var ssNum =0;
        var totalNum =alertList.length;
        for (i=0; i< alertList.length; i++){
            updateAlert = alertList[i]
            if(updateAlert.length == 4){
                ssNum ++
            }
        }
        if(ssNum == totalNum){
            res.send('OK, scan '+ ssNum + '/' + totalNum)
        }else{
            res.status(404).send('Error, parsed ' +  String(totalNum - ssNum)  + '/' + totalNum)
        }
    }else{
        res.status(404).send("Error fomat");
    }
});





app.listen(8000, () => {
  console.log('Test server listenning on port 8000!')
});

