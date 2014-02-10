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
 * controlAppDelegate.h
 *
 */

#import <Cocoa/Cocoa.h>
#import "kernelControl.h"

@interface controlAppDelegate : NSObject <NSApplicationDelegate>

@property (assign) IBOutlet NSWindow *window;
@property (weak) IBOutlet NSTextField *statusField;
@property (weak) IBOutlet NSButton *connectButton;
@property (weak) IBOutlet NSButton *disconnectButton;
@property (weak) IBOutlet NSImageView *status;
@property (weak) IBOutlet NSButton *ptraceButton;
@property (weak) IBOutlet NSButton *sysctlButton;
@property (weak) IBOutlet NSButton *resumeFlagButton;
@property (weak) IBOutlet NSButton *taskForPidButton;
@property (weak) IBOutlet NSButton *kauthButton;
@property (weak) IBOutlet NSButton *singleStepButton;

- (IBAction)pressConnect:(id)sender;
- (IBAction)pressDisconnect:(id)sender;
- (IBAction)takePtrace:(id)sender;
- (IBAction)takeSysctl:(id)sender;
- (IBAction)takeResumeFlag:(id)sender;
- (IBAction)takeTaskForPid:(id)sender;
- (IBAction)takeKauth:(id)sender;
- (IBAction)takeSingleStep:(id)sender;

-(void)disableOptionButtons;
-(void)enableOptionButtons;

@property (strong) KernelControl *kc;

@end
