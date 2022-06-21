/*!
     * Copyright 2017-2017 Mutual of Enumclaw. All Rights Reserved.
     * License: Public
*/ 

//Mutual of Enumclaw 
//
//Matthew Hengl and Jocelyn Borovich - 2019 :) :)
//
//Main file that controls remediation and notifications for all CloudTrail changes. 
//Remediates actions when possible or necessary based on launch type and tagging. Then, notifies the user/security. 

//Make sure to that the master.invalid call does NOT have a ! infront of it
//Make sure to delete or comment out the change in the process.env.environtment

const AWS = require('aws-sdk');
AWS.config.update({region: process.env.region});
const Master = require("aws-automated-master-class/MasterClass").handler;
const master = new Master();
let ec2 = new AWS.EC2();
let path = require("aws-automated-master-class/MasterClass").path;

let improperLaunch = false;
//Variables that allow these functions to be overridden in Jest testing by making the variable = jest.fn() 
//instead of its corresponding function
let callAutoTag = autoTag;
let callCheckTagsAndAddToTable = checkTagsAndAddToTable;
let callRemediate = remediate;
let callRemediateDynamo = remediateDynamo;
let callHandler = handleEvent;
let callFindId = findId;

//Only used for testing purposes
setEc2Function = (value, funct) => {
     ec2[value] = funct;
};

async function handleEvent(event){

     let resourceName = '';
     console.log(JSON.stringify(event));
     path.p = 'Path: \nEntered handleEvent';

     if(master.checkDynamoDB(event)){

          //Converts the event into an unmarshalled event so we can use resources from the dynamo event
          let convertedEvent = master.dbConverter(event);
          console.log(convertedEvent);

          //extra console.log statements for testing ===================
          if(convertedEvent.ResourceName){
               console.log(`DynamoDB event "${convertedEvent.ResourceName}" is being inspected-------------`);
          }else{
               console.log(`DynamoDB event "${event.Records[0].dynamodb.Keys.ResourceName.S}" is being inspected!-----------`);
          }

          //If statement to check to see if the event coming from DynamoDB is a 'REMOVE' event and a EC2 Resource
          if(convertedEvent.ResourceType == 'EC2' && event.Records[0].eventName == 'REMOVE'){
               path.p += '\nEvent is of type EC2 and has an event of REMOVE'; //Adds to the path
               try{
                    //Creating an object so we can check the tags on the resource coming from DynamoDB
                    let params = {
                         Filters: [
                              {
                                   Name: 'resource-id',
                                   Values: [
                                        event.Records[0].dynamodb.Keys.ResourceName.S
                                   ]
                              }
                         ]
                    };
                    //Calling a function from the API SDK and saving the results to the variable 'tags'
                    tags = await ec2.describeTags(params).promise();
                    console.log(tags);
                    //If statement to check if the correct tags are attached to the resource that is being inspected
                    if(!(master.tagVerification(tags.Tags))){
                         path.p += '\nResource has the incorrect tags'; //Adds to the path
                         //Calling notifyUser in the master class, as a parameter, also calls RemediateDynamo to remediate and return a results to use in notify
                         await master.notifyUser(event, await callRemediateDynamo(event, convertedEvent), 'EC2');
                    };
               //Catch statement to catch an error if one were to appear in the try statement above
               }catch(e){
                    console.log(e);
                    path.p += '\nERROR';
                    console.log(path.p);
                    return e;
               }
          }else{
               //If the event is not of event 'REMOVE' and not of EC2 resource, will add to path and stop the program
               path.p += '\nEvent was not of type EC2 and/or didn\'t have an event of REMOVE'
               return;
          }
          //prints out the path and returns to stop the program
          console.log(path.p);
          return;
     };
     try{

          event = master.devTest(event);
          //checks if there is an error in the log
          if(master.errorInLog(event)){
               console.log(path.p);
               // path.p = '';
               return;
          };

          //Checks if the log came from this function, quits the program if it does.
          if (master.selfInvoked(event)) {
               console.log(path.p);
               // path.p = '';
               return;
          };

          console.log(`Event action is ${event.detail.eventName}------------------------`);

          //if(master.checkKeyUser(event)){
               if(master.invalid(event)){
                    improperLaunch = true;
                    console.log('Calling notifyUser');

                    await master.notifyUser(event, await callRemediate(event), 'EC2');

                    console.log(path.p);
                    return;
               }
               if(event.detail.eventName == 'DeleteKeyPair' || event.detail.eventName == 'ModifyInstanceAttribute' 
                    || event.detail.eventName == 'RebootInstances' || event.detail.eventName == 'TerminateInstances'){
                         console.log('Calling notifyUser');
                         await master.notifyUser(event, await callRemediate(event), 'EC2');
               }else{
                    console.log('Calling CheckTagsAndAddToTable');
                    await callCheckTagsAndAddToTable(event);
               }
               console.log(path.p);
          //};
     }catch(e){
          console.log(e);
          path.p += '\nERROR';
          console.log(path.p);
          return e;
     };
};
//This function is checking the tags on the resource and adding them if needed. If tags were added then it will add the resource to the DynamoDB table.
async function checkTagsAndAddToTable(event){
     console.log('Entered checkTagsAndAddToTable');
     console.log(event);
     path.p  += '\nEntered checkTagsAndAddToTable, Created params for function calls';
     try{
          console.log('Calling autoTag');
          path.p += '\nCalling AutoTag function'; //Adds to the pathing
          tags = await callAutoTag(event, findId(event)); //Calls autoTag to auotmatically tag the resource that is coming through
          //As a parameter, also calls findId which will find the correct ID for the remediation to continue
          console.log(tags);
          //If statement to check if the correct tags are attached to the resource that is being inspected
          //Returns true if the resource as the wrong tags and returns false if the resource has the correct tags.
          console.log('Checking tags');
          if(!(master.tagVerification(tags.Tags))){
               //Calls a function in masterClass which will put the item in the DynamoDB table
               // process.env.environment = 'snd';
               await master.putItemInTable(event, 'EC2', findId(event));
               console.log('Returning true');
               return true;
          }else{
               console.log('Returning false');
               return false; //Not getting hit in the jest file
          }
     }catch(e){
          console.log(e);
          path.p += '\nERROR';
          // console.log(path.p);
          return e;     
     }
};

async function remediate(event){

     console.log('Entered remediate');
     path.p += '\nEntered the remediation function';
     const erp = event.detail.requestParameters;
     const ere = event.detail.responseElements;

     let params = {};

     let results = master.getResults(event, {});
     try{
          switch(results.Action){
               //Case statement for CreateKeyPair
               case 'CreateKeyPair':
                    path.p += '\nCreateKeyPair';
                    // params.KeyName = findId(event);
                    // await ec2.deleteKeyPair(params).promise();
                    // results.ResourceName = params.KeyName;
                    // results.Reponse = 'DeleteKeyPair';
                    await callRemediateDynamo(event, results);
                    results.ResourceName = findId(event);
                    results.Reponse = 'DeleteKeyPair';
               break;
               //Case statement for DeleteKeyPair
               case 'DeleteKeyPair':
                    path.p += '\nDeleteKeyPair';
                    results.ResourceName = erp.keyName;
                    results.Reponse = 'Remediation could not be performed';
               break;
               //Case statement for ModifyInstanceAttribute
               case 'ModifyInstanceAttribute':
                    path.p += '\nModifyInstanceAttribute';
                    results.ResourceName = erp.instanceId;
                    results.Reponse = 'Remediation could not be performed';
               break;
               //Case statement for RebootInstances
               case 'RebootInstances':
                    path.p += '\nRebootInstances';
                    results.ResourceName = erp.instancesSet.items[0].instanceId;
                    results.Reponse = 'Remediation could not be performed';
               break;
               //Case statement for RunInstances
               case 'RunInstances':
                    path.p += '\nRunInstances';
                    // await remediateDynamo(event, results);
                    await callRemediateDynamo(event, results);                    
                    results.ResourceName = findId(event);
                    results.Reponse = 'TerminateInstances';
               break;
               //Case statement for StartInstances
               case 'StartInstances':
                    path.p += '\nStartInstances';
                    // params.InstanceIds.push(findId(event));
                    // await ec2.stopInstances(params).promise();
                    // results.ResourceName = params.InstanceIds;
                    // results.Reponse = 'StopInstances';
                    await callRemediateDynamo(event, results);                    
                    results.ResourceName = findId(event);
                    results.Reponse = 'TerminateInstances';
               break;
               //Case statement for StopInstances
               case 'StopInstances':
                    path.p += '\nStopInstances';
                    // params.InstanceIds.push(findId(event));
                    // results.ResourceName = params.InstanceIds;
                    // results.Reponse = 'StartInstances';
                    await callRemediateDynamo(event, results);                    
                    results.ResourceName = findId(event);
                    results.Reponse = 'TerminateInstances';
               break;
               //Case statement for TerminateInstances
               case 'TerminateInstances':
                    path.p += '\nTerminateInstances';
                    results.ResourceName = erp.instancesSet.items[0].instanceId;
                    results.Reponse = 'Remediation could not be performed';
               break;
          }
     //Catch statement 
     }catch(e){
          console.log(e);
          path.p += '\nERROR';
          // console.log(path.p);
          return e; 
     }
     if(results.Response == 'Remediation could not be performed'){
          delete results.Reason;
     }
     path.p += '\nRemediation was finished';
     // console.log(results);
     return results;
};
//Remediate Dynamo function which will handle the event that is coming in from DynamoDB as well as handling some creation functions.
async function remediateDynamo(event, results){
     console.log(results);
     path.p += '\nEntered RemediateDynamo';
     let params = {};
     try{
          //If statement to find out if the event is DynamoDB or not by calling the function checkDynamoDB in masterClass
          if(master.checkDynamoDB(event)){
               console.log('Event is dynamoDB');
               //If statemenet used to find out if the event is an instance event or a key pair event
               if(results.Action.toLowerCase().includes('instance')){

                    params.InstanceIds = []; //Creating a property inside of params named InstanceIds
                    console.log('instance');
                    params.InstanceIds.push(results.ResourceName); //Pushing the resource name to be the first thing in the array
                    await overrideFunction('terminateInstances', params);
                    path.p += `\n${params.InstanceIds}`;

               }else{
                    console.log('key pair');
                    let listParams = {
                         Filters: [
                              {
                                   Name: 'resource-id',
                                   Values: [
                                        results.ResourceName
                                   ]
                              }
                         ]
                    };
                    tags = await ec2.describeTags(listParams).promise(); //calls describe to save the array to tags
                    //FindIndex being used to see if the tag of 'KeyName' is in the array
                    let tagFound = (element) => element.Key == 'KeyName';
                    let tagPlaceHolder = tags.Tags.findIndex(tagFound);
                    //If there is an outcome other than -1, then save the content of the tag as KeyName
                    if(tagPlaceHolder != -1){
                         params.KeyName = tags.Tags[tagPlaceHolder].Value;
                         path.p += `\n${params.KeyName}`;
                    }
                    console.log(tags);
                    await overrideFunction('deleteKeyPair', params);
                    path.p += `\nDelete Key Pair`;
               }
               console.log('Deleted instance/Key pair');
          }else{
               //Else statement if the event is not DynamoDB
               console.log('Event is not DynamoDB');
               if(results.Action.toLowerCase().includes('instances')){
                    console.log('Instance');
                    params.InstanceIds = [];//Creating a property inside of params named InstanceIds
                    params.InstanceIds.push(findId(event));//Pushing the resource name to be the first thing in the array
                    await overrideFunction('terminateInstances', params);
                    path.p += `\n${params.InstanceIds}`;
               }else{
                    console.log('KeyPair');
                    params.KeyName = event.detail.responseElements.keyName;
                    await overrideFunction('deleteKeyPair', params);
                    path.p += `\n${params.KeyName}`;
               }
          }
          return results;
     }catch(e){
          console.log(e);
          path.p += '\nERROR';
          // console.log(path.p);
          return e; 
     }
};
//Function that will automatically add the correct tag to the resource
async function autoTag(event, id){
     console.log('Entered autoTag');
     path.p += '\nEntered AutoTag';

     console.log(id);
     let params = {};

     //Created a variable that will be used to get the tags attached to the resource
     let listParams = {
          Filters: [
               {
                    Name: 'resource-id',
                    Values: [
                         id
                    ]
               }
          ]
     };
     try{
          tags = await ec2.describeTags(listParams).promise(); //Calls describeTags to save the array as a variable named tags
          params.Resources = [id];
          console.log(params);

          //If statement that will check to see if the resource was being made in sandbox or not
          //If it was made in sandbox, it will add the 'tag3' tag to the resource
          if(master.snd(event) && master.needsTag(tags.Tags, `${process.env.tag3}`)){
               console.log(`Checking for ${process.env.tag3}`);
               path.p += `\nAdding ${process.env.tag3}`;
               await ec2.createTags(await master.getParamsForAddingTags(event, params, `${process.env.tag3}`)).promise();
          }
          //If statment to check to see if the resource needs to the tag of 'Environment'
          if(master.needsTag(tags.Tags, 'Environment')){
               console.log('Checking for Environment');
               path.p += `\nAdding Environment`;
               await ec2.createTags(await master.getParamsForAddingTags(event, params, `Environment`)).promise();
          }
          //If the resource has the event name of 'CreateKeyPair', then the keyName will be add to the resource as a tag to be used later.
          if(event.detail.eventName == 'CreateKeyPair'){
               path.p += '\nAdding KeyName';
               params.Resources = [event.detail.responseElements.keyPairId];
               params.Tags = [{Key: 'KeyName', Value: event.detail.responseElements.keyName}];
               await ec2.createTags(params).promise();
          }
          path.p += '\nAutoTag Complete';
          tags = await ec2.describeTags(listParams).promise();
          console.log(tags);
          return tags;
     }catch(e){
          console.log(e);
          path.p += '\nERROR';
          // console.log(path.p);
          return e;   
     }
};
//This function will return the correct Id depending on the eventName coming through
function findId(event){
     path.p += '\nEntered findId';
     try{
          switch(event.detail.eventName){
               case 'StartInstances':
               case 'StopInstances':
                    console.log(event.detail.requestParameters.instancesSet.items[0].instanceId);
                    path.p += `\nFinding Id for ${event.detail.eventName}`;
                    return event.detail.requestParameters.instancesSet.items[0].instanceId;
               case 'CreateKeyPair':
                    console.log(event.detail.responseElements.keyPairId);
                    path.p += `\nFinding Id for CreateKeyPair`;
                    return event.detail.responseElements.keyPairId;
               case 'RunInstances':
                    console.log(event.detail.responseElements.instancesSet.items[0].instanceId);
                    path.p += `\nFinding Id for RunInstances`;
                    return event.detail.responseElements.instancesSet.items[0].instanceId;
          }
     }catch(e){
          console.log(e);
          path.p += '\nERROR';
          // console.log(path.p);
          return e; 
     }
};

async function overrideFunction(apiFunction, params){
     if(process.env.run == 'false'){
       await setEc2Function(apiFunction, (params) => {
         console.log(`Overriding ${apiFunction}`);
         return {promise: () => {}};
       });
     }
     await ec2[apiFunction](params).promise();
};

//This block of exports allow us to export not only our handler to execute but also other functions for testing purposes
exports.handler = handleEvent;
exports.checkTagsAndAddToTable = checkTagsAndAddToTable; 
exports.remediateDynamo = remediateDynamo;
exports.autoTag = autoTag;
exports.remediate = remediate;
exports.findId = findId;

// This export function allows us the ability to override certain functions.
// Here' we would give the value as the API function call from the SDK in which we want to over ride, then the funct would be what we want it to acctually do
// Example from a jest file:
// await main.setEc2Function('describeTags', (params) => {
//      return {promise: () => {throw new Error()}};
//  });
//Anything can be in the function that is being returned as a promise. DOES NOT ALWAYS HAVE TO BE THROW NEW ERROR
exports.setEc2Function = (value, funct) => {
     ec2[value] = funct;
};
exports.setDBFunction = (value, funct) => {
     dynamodb[value] = funct;
};
//These export functions allows us to create fake jest functions in a jest file so we can simulate them without executing them
exports.setHandler = (funct) => {
     callHandler = funct;
};
exports.setAutoTag = (funct) => {
     callAutoTag = funct;
};
exports.setRemediate = (funct) => {
     callRemediate = funct;
};
exports.setRemediateDynamo = (funct) => {
     callRemediateDynamo = funct;
};
exports.setCheckTagsAndAddToTable = (funct) => {
     callCheckTagsAndAddToTable = funct;
};
exports.setFindId = (funct) => {
     callFindId = funct;
}