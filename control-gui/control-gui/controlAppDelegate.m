/*
 * ________
 * \_____  \   ____ ___.__.___  ___
 *  /   |   \ /    <   |  |\  \/  /
 * /    |    \   |  \___  | >    <
 * \_______  /___|  / ____|/__/\_ \
 *         \/     \/\/           \/
 *                    The Black Cat
 *
 * Copyright (c) fG!, 2011, 2012, 2013, 2014 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * controlAppDelegate.m
 *
 */

#import "controlAppDelegate.h"
#import "kernelControl.h"
#import "shared_data.h"

@implementation controlAppDelegate


- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    self.kc = [KernelControl new];
    if ( [self.kc connectToKext] == 0 )
    {
        [self.statusField setStringValue:@"Connected to kext!"];
        [self.disconnectButton setEnabled:YES];
        [self.connectButton setEnabled:NO];
        NSImage *connectedImage = [NSImage imageNamed:@"status-available.tiff"];
        [self.status setImage:connectedImage];
        [self enableOptionButtons];
    }
    else
    {
        [self.statusField setStringValue:@"Failed to connect to kext!"];
        [self.disconnectButton setEnabled:NO];
        [self.connectButton setEnabled:YES];
        [self disableOptionButtons];
    }
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender
{
    return YES;
}

-(void)enableOptionButtons
{
    [self.ptraceButton setEnabled:YES];
    [self.sysctlButton setEnabled:YES];
    [self.resumeFlagButton setEnabled:YES];
    [self.taskForPidButton setEnabled:YES];
    [self.kauthButton setEnabled:YES];
    [self.singleStepButton setEnabled:YES];
}

-(void)disableOptionButtons
{
    [self.ptraceButton setEnabled:NO];
    [self.sysctlButton setEnabled:NO];
    [self.resumeFlagButton setEnabled:NO];
    [self.taskForPidButton setEnabled:NO];
    [self.kauthButton setEnabled:NO];
    [self.singleStepButton setEnabled:NO];
}

- (IBAction)pressConnect:(id)sender
{
    if ( [self.kc connectToKext] == 0 )
    {
        [self.statusField setStringValue:@"Connected to kext!"];
        [self.disconnectButton setEnabled:YES];
        [self.connectButton setEnabled:NO];
        NSImage *connectedImage = [NSImage imageNamed:@"status-available.tiff"];
        [self.status setImage:connectedImage];
        [self enableOptionButtons];
    }
    else
    {
        [self.statusField setStringValue:@"Failed to connect to kext!"];
        [self.disconnectButton setEnabled:NO];
        [self disableOptionButtons];
    }
}

- (IBAction)pressDisconnect:(id)sender
{
    [self.kc disconnectFromKext];
    [self.statusField setStringValue:@"Disconnected from kext!"];
    [self.disconnectButton setEnabled:NO];
    [self.connectButton setEnabled:YES];
    NSImage *connectedImage = [NSImage imageNamed:@"status-away.tiff"];
    [self.status setImage:connectedImage];
    [self disableOptionButtons];
}

- (IBAction)takePtrace:(id)sender
{
    if ( [[sender cell] state] == NSOnState)
    {
        [self.kc sendCommand:ANTI_PTRACE_ON];
        [self.statusField setStringValue:@"Enabled anti-anti-ptrace!"];
    }
    else if ( [[sender cell] state] == NSOffState)
    {
        [self.kc sendCommand:ANTI_PTRACE_OFF];
        [self.statusField setStringValue:@"Disabled anti-anti-ptrace!"];
    }
}

- (IBAction)takeSysctl:(id)sender
{
    if ( [[sender cell] state] == NSOnState)
    {
        [self.kc sendCommand:ANTI_SYSCTL_ON];
        [self.statusField setStringValue:@"Enabled anti-sysctl-antidebugging!"];
    }
    else if ( [[sender cell] state] == NSOffState)
    {
        [self.kc sendCommand:ANTI_SYSCTL_OFF];
        [self.statusField setStringValue:@"Disabled anti-sysctl-antidebugging!"];
    }
}

- (IBAction)takeResumeFlag:(id)sender
{
    if ( [[sender cell] state] == NSOnState)
    {
        [self.kc sendCommand:PATCH_RESUME_FLAG];
        [self.statusField setStringValue:@"Patched resume flag!"];
    }
    else if ( [[sender cell] state] == NSOffState)
    {
        [self.kc sendCommand:UNPATCH_RESUME_FLAG];
        [self.statusField setStringValue:@"Restored resume flag!"];
    }
}

- (IBAction)takeTaskForPid:(id)sender
{
    if ( [[sender cell] state] == NSOnState)
    {
        [self.kc sendCommand:PATCH_TASK_FOR_PID];
        [self.statusField setStringValue:@"Enabled task_for_pid(0)!"];
    }
    else if ( [[sender cell] state] == NSOffState)
    {
        [self.kc sendCommand:UNPATCH_TASK_FOR_PID];
        [self.statusField setStringValue:@"Disabled task_for_pid(0)!"];
    }
}

- (IBAction)takeKauth:(id)sender {
    if ( [[sender cell] state] == NSOnState)
    {
        [self.kc sendCommand:ANTI_KAUTH_ON];
        [self.statusField setStringValue:@"Patched kauth anti-debugging!"];
    }
    else if ( [[sender cell] state] == NSOffState)
    {
        [self.kc sendCommand:ANTI_KAUTH_OFF];
        [self.statusField setStringValue:@"Restored kauth anti-debugging!"];
    }
}

- (IBAction)takeSingleStep:(id)sender
{
    if ( [[sender cell] state] == NSOnState)
    {
        [self.kc sendCommand:PATCH_SINGLESTEP];
        [self.statusField setStringValue:@"Enabled single step!"];
    }
    else if ( [[sender cell] state] == NSOffState)
    {
        [self.kc sendCommand:UNPATCH_SINGLESTEP];
        [self.statusField setStringValue:@"Disabled single step!"];
    }
}

@end
