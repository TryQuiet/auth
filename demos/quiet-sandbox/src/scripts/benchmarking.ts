import { SigChain } from '../auth/chain.js'
import { UserService } from "../auth/services/members/userService.js";
import { program } from '@commander-js/extra-typings'
import { LocalUserContext } from '@localfirst/auth';
import { Networking, LocalStorage } from '../network.js';

import chalk from 'chalk'
import fs from 'fs'
import { notEqual } from 'assert';

const writeBenchmark = (csvFile: fs.WriteStream, action: string, storage: LocalStorage, start: number, end: number) => {
  if (storage.getContext() == null) {
    console.log("No context has been setup!  Please join a team and then check back!")
    return
  }
  const actor = storage.getContext()!.user.userName
  let roleCount, roleDetails, roles, memberCount, teamKeyGeneration;
  if (storage.getSigChain() == null) {
    roleCount = 0
    roleDetails = {}
    memberCount = 0
    teamKeyGeneration = "N/A"
  }
  else {
    roles = storage.getSigChain()!.roles.getAllRoles(storage.getContext()!) || {};
    roleCount = roles.length;
    roleDetails = roles.map(role => ({
        roleName: role.roleName,
        generation: storage.getSigChain()!.team.roleKeysAllGenerations(role.roleName).slice(-1)[0].generation
    })) || {};
    memberCount = storage.getSigChain()!.users.getAllMembers().length || "N/A";
    teamKeyGeneration = storage.getSigChain()!.team.teamKeys().generation || "N/A";
  }
  const actionDuration = end - start;

  // Convert roleDetails to JSON string and escape double quotes
  const roleDetailsJson = JSON.stringify(roleDetails).replace(/"/g, '""');

  const csvLine = `${action},${actor},${actionDuration},${memberCount},${roleCount},${teamKeyGeneration},"${roleDetailsJson}"\n`;
  csvFile.write(csvLine);
}


export const benchmark = async (filename: string="./benchmarks/benchmark.csv") => {
  console.log(chalk.magentaBright.bold.underline("Benchmarking"));
  //
  let start, end: number
  let networking: Networking | undefined
  let storage = new LocalStorage();
  let csvFile: fs.WriteStream

  const teamName = 'benchmark-team'
  const username = 'founder'

  // Open a csv file to write the results to
  // create any directories needed
  const dir = filename.split('/').slice(0, -1).join('/')
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(`${dir}`, { recursive: true })
  }
  csvFile = fs.createWriteStream(`${filename}`)
  // Write the header row
  csvFile.write('action,actor,ms,members,n_roles,team_key_gen,roles\n')


  // Benchmark the creation of a team
  start = Date.now()
  const loadedSigChain = SigChain.create(teamName, username);
  storage.setContext(loadedSigChain.context)
  storage.setSigChain(loadedSigChain.sigChain)
  storage.setAuthContext({
    user: loadedSigChain.context.user,
    device: loadedSigChain.context.device,
    team: loadedSigChain.sigChain.team
  })

  start = Date.now()
  networking = await Networking.init(storage)
  end = Date.now()
  writeBenchmark(csvFile, 'networking.init', storage, start, end)

  const founderAddress = networking.libp2p.libp2p?.getMultiaddrs()[0].toString();

  // create an invite
  start = Date.now()
  const invite = storage.getSigChain()!.invites.create(undefined, 1000)
  end = Date.now()
  writeBenchmark(csvFile, 'invites.create', storage, start, end)

  // Invite members
  let storages: LocalStorage[] = []
  let networkings: Networking[] = []
  for (let i = 0; i < 100; i++) {

    // create a new member
    start = Date.now()
    const newUsername = `b${i}`
    console.log(`Creating new user ${newUsername}`)
    storages.push(new LocalStorage())
    const lastStorage = storages[storages.length - 1]
    const prospectiveUser = UserService.createFromInviteSeed(newUsername, invite.seed)
    lastStorage.setContext(prospectiveUser.context)
    lastStorage.setAuthContext({
      user: prospectiveUser.context.user,
      device: prospectiveUser.context.device,
      invitationSeed: invite.seed
    })
    end = Date.now()
    writeBenchmark(csvFile, 'UserService.createFromInviteSeed', lastStorage, start, end)

    // founder adds the member
    start = Date.now()
    console.log(`Admitting member ${newUsername}`)
    storage.getSigChain()!.invites.admitMemberFromInvite(
      prospectiveUser.inviteProof,
      lastStorage.getContext()!.user.userName,
      lastStorage.getContext()!.user.userId,
      prospectiveUser.publicKeys
    )
    end = Date.now()
    writeBenchmark(csvFile, 'invites.admitMemberFromInvite', storage, start, end)

    // serialize the team to simulate sending to the new member
    start = Date.now()
    console.log(`Serializing team for ${newUsername}`)
    const savedChain = storage.getSigChain()!.team.save()
    end = Date.now()
    writeBenchmark(csvFile, 'team.save', storage, start, end)

    // get the team Keyring
    start = Date.now()
    console.log(`Getting team keyring for ${newUsername}`)
    const teamKeyRing = storage.getSigChain()!.team.teamKeyring()
    end = Date.now()
    writeBenchmark(csvFile, 'team.teamKeys', storage, start, end)

    // // new user joins the team
    start = Date.now()
    console.log(`Joining team for ${newUsername}`)
    const {
      sigChain,
      context
    } = SigChain.join(lastStorage.getContext()!, savedChain, teamKeyRing)
    end = Date.now()
    writeBenchmark(csvFile, 'team.join', storage, start, end)

    start = Date.now()
    console.log(`Setting sig chain for ${newUsername}`)
    lastStorage.setSigChain(sigChain)
    end = Date.now()
    writeBenchmark(csvFile, 'storage.setSigChain', storage, start, end)

    start = Date.now()
    console.log(`Setting context for ${newUsername}`)
    lastStorage.setContext(context)
    end = Date.now()
    writeBenchmark(csvFile, 'storage.setContext', storage, start, end)


    // networking
    // start = Date.now()
    // console.log(`Creating networking for ${newUsername}`)
    // networkings.push(await Networking.init(lastStorage))
    // const lastNetworking = networkings[networkings.length - 1]
    // end = Date.now()
    // writeBenchmark(csvFile, 'networking.init', storage, start, end)

    // // dial the founder
    // start = Date.now()
    // const success = await lastNetworking.libp2p.dial(`/${founderAddress}`)
    // console.log(`Dialing was successful: ${success}`)
    // end = Date.now()
    // writeBenchmark(csvFile, 'networking.dial', storage, start, end)

    // join the team

    // writeBenchmark(csvFile, 'networking.joined', storage, start, end)

    // disconnect
    // start = Date.now()
    // await lastNetworking.close()
    // end = Date.now()
    // writeBenchmark(csvFile, 'networking.close', storage, start, end)

    // check if the member was added
    start = Date.now()
    let hasRole = storage.getSigChain()!.team.memberHasRole(storage.getContext()!.user.userId, 'member')
    console.log(`Member ${newUsername} has role: ${hasRole}`)
    end = Date.now()
    writeBenchmark(csvFile, 'team.hasRole', storage, start, end)

    // remove member
    // start = Date.now()
    // console.log(`Removing member ${newUsername}`)
    // storage.getSigChain()!.team.remove(lastStorage.getContext()!.user.userId)
    // end = Date.now()
    // writeBenchmark(csvFile, 'team.remove', storage, start, end)
  }


  // for (let i = 0; i < storages.length; i++) {
  //   start = Date.now()
  //   await networkings[i].close()
  //   end = Date.now()
  //   writeBenchmark(csvFile, 'networking.close', storage, start, end)
  // }
  start = Date.now()
  networking.close()
  end = Date.now()
  writeBenchmark(csvFile, 'networking.close', storage, start, end)
}
