#! /usr/bin/env ts-node

import inquirer from 'inquirer';
import chalk from 'chalk';

import actionSelect from '../components/actionSelect.js';
import { teamAdd, teamInfo } from './team.js';
import channelsList from './channelsList.js';
import usersList from './users.js';
import rolesList from './rolesList.js';
import invitesList from './invitesList.js';
import { Storage } from '../network.js';

const interactive = async () => {
  const storage = new Storage()

  console.log(chalk.magentaBright.bold.underline("Quiet Sandbox"));
  console.log("Navigate options with arrow keys, use E to select, and Q to go back.");
  let exit = false;
  while (exit === false) {
    const answer = await actionSelect(
        {
          message: chalk.bold("Main Menu"),
          choices: [
            { name: "Team", value: "team", description: "Explore team information"},
            { name: "Channels", value: "channels", description: "Explore channels" },
            { name: "Users", value: "users", description: "Explore users" },
            { name: "Roles", value: "roles", description: "Explore roles" },
            { name: "Invites", value: "invites", description: "Explore invites" },
          ],
          actions: [
            { name: "Select", value: "select", key: "e" },
            { name: 'Add', value: "add", key: "a" },
            { name: "Exit Program", value: "exit", key: "escape" },
          ]
        },
      )
    switch (answer.action) {
      case "select":
      case undefined: // catches enter/return key
        switch (answer.answer) {
          case "team":
            teamInfo(storage);
            break;
          case "channels":
            await channelsList();
            break;
          case "users":
            await usersList();
            break;
          case "roles":
            await rolesList();
            break;
          case "invites":
            await invitesList();
            break;
        }
        break;
      case "add":
        switch (answer.answer) {
          case "team":
            await teamAdd(storage)
            break
          // case "invites":
          //   await 
          case undefined:
            break
        }
        break;
      case "exit":
        exit = true;
        break;
    }
  };
  console.log(chalk.magentaBright.bold("Goodbye!"));
};

export default interactive;
