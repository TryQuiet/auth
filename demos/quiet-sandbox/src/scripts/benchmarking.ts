import { SigChain } from '../auth/chain.js'
import { UserService } from "../auth/services/members/userService.js";
import { program } from '@commander-js/extra-typings'
import { LocalUserContext } from '@localfirst/auth';

import chalk from 'chalk'
import fs from 'fs'

const writeBenchmark = (csvFile: fs.WriteStream, action: string, context: LocalUserContext, sigChain: SigChain, start: number, end: number) => {
  const roles = sigChain.roles.getAllRoles(context);
  const actionDuration = end - start;
  const memberCount = sigChain.users.getAllMembers().length;
  const roleCount = roles.length;
  const roleDetails = roles.map(role => ({
      roleName: role.roleName,
      generation: sigChain.team.roleKeysAllGenerations(role.roleName).slice(-1)[0].generation
  }));
  const teamKeyGeneration = sigChain.team.teamKeys().generation;

  // Convert roleDetails to JSON string and escape double quotes
  const roleDetailsJson = JSON.stringify(roleDetails).replace(/"/g, '""');

  const csvLine = `${action},${actionDuration},${memberCount},${roleCount},${teamKeyGeneration},"${roleDetailsJson}"\n`;
  csvFile.write(csvLine);
}


export const benchmark = async () => {
  console.log(chalk.magentaBright.bold.underline("Benchmarking"));

  //
  const teamName = 'benchmark-team'
  const username = 'founder'

  // Check for previous benchmark results and assign a new benchmark ID
  // let runNum = 1
  // while (fs.existsSync(`./benchmarks/benchmark-${runNum}.csv`)) {
  //   runNum++
  // }

  // Create benchmarks directory
  if (!fs.existsSync('./benchmarks')) {
    fs.mkdirSync('./benchmarks')
  }

  // Open a csv file to write the results to
  const csvFile = fs.createWriteStream(`./benchmarks/benchmark.csv`)
  // Write the header row
  csvFile.write('action,ms,members,n_roles,team_key_gen,roles\n')

  // Benchmark the creation of a team
  let start = Date.now()
  const { context, sigChain } = SigChain.create(teamName, username)
  let end = Date.now()
  writeBenchmark(csvFile, 'team.create', context, sigChain, start, end)

  // create an invite
  start = Date.now()
  const invite = sigChain.invites.create(undefined, 1000)
  end = Date.now()
  writeBenchmark(csvFile, 'invites.create', context, sigChain, start, end)

  // Invite members
  for (let i = 0; i < 100; i++) {
    // create a new member
    const newUsername = `b${i}`
    let prospectiveMember = UserService.createFromInviteSeed(newUsername, invite.seed)

    // join the team
    start = Date.now()
    sigChain.invites.admitMemberFromInvite(
      prospectiveMember.inviteProof,
      prospectiveMember.context.user.userName,
      prospectiveMember.context.user.userId,
      prospectiveMember.publicKeys
    )
    end = Date.now()
    writeBenchmark(csvFile, 'invites.admitMember', context, sigChain, start, end)


    // serialize team graph
    start = Date.now()
    sigChain.team.save()
    end = Date.now()
    writeBenchmark(csvFile, 'team.save', context, sigChain, start, end)

    // check if the member was added
    start = Date.now()
    let hasRole = sigChain.team.memberHasRole(context.user.userId, 'member')
    console.log(`Member ${newUsername} has role: ${hasRole}`)
    end = Date.now()
    writeBenchmark(csvFile, 'team.hasRole', context, sigChain, start, end)

  }

  // remove member from role
  for (const user of sigChain.users.getAllMembers()) {
    start = Date.now()
    sigChain.team.removeMemberRole(user.userId, 'member')
    end = Date.now()
    writeBenchmark(csvFile, 'users.remove', context, sigChain, start, end)
  }
}
