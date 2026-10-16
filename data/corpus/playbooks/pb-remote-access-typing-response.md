# Responding to typing through a remote-access tool

## When to use

Use this playbook when Continuum has recorded a remote_access_input
incident: typing that Windows reported as created by software, with no
physical keyboard behind it, while a remote-access tool such as AnyDesk,
TeamViewer, RustDesk, UltraViewer, ScreenConnect or Quick Assist was
running. The usual story is a phone call from someone claiming to be
technical support, a bank or a delivery company, who talks the user into
installing a remote-access tool and then takes control of the computer.

## Steps

1. Keep the workstation locked until you know who was connected. The
   incident lists which remote-access tools were running at the time.
2. Disconnect the computer from the network, Wi-Fi included, before
   signing back in, so the remote session cannot resume.
3. Sign in and open the remote-access tool's own connection history.
   AnyDesk and TeamViewer both keep a list of incoming sessions with the
   remote id and the time. Write down every session the user did not
   start themselves.
4. Uninstall any remote-access tool the user did not knowingly install,
   or install for a session they now regret. Do not just close it, since
   many of these tools run as a service and start again on their own.
5. Ask the user what the caller wanted and what happened on screen. A
   request to open online banking, to buy gift cards, or to read out a
   one-time code means the caller was after money.
6. Change every password typed or visible during the session, starting
   with email and banking, from a different, trusted device. Turn on
   two-step verification where it is offered.
7. If banking was open or money was mentioned, contact the bank at once
   using the number on the back of the card.
8. Check for anything the caller left behind: new user accounts, newly
   installed programs, browser extensions and scheduled tasks.
9. Report the scam to the national cybercrime reporting service. In
   India that is cybercrime.gov.in or the 1930 helpline.

## Using the allow switch safely

Continuum's dashboard has an Allow remote access button on the Live
status page for when the owner of the computer really is using a
remote-access tool. Turn it on only for a session you started yourself,
for the shortest time that works, and turn it off with Stop allowing as
soon as the session ends. Never turn it on because someone on the phone
asks you to.

## Common mistakes

- Unlocking the computer while still connected to the network, which
  lets the remote session pick up where it left off.
- Closing the remote-access tool's window and assuming it has gone. Most
  keep running in the background.
- Calling back the number the caller gave to check whether the call was
  real. Use a number from an official source instead.
- Treating the incident as a false alarm because the user installed the
  tool themselves. Installing it at a stranger's request is how these
  scams work.
