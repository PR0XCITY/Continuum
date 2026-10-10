# Triage checklist for suspected BadUSB or Rubber Ducky activity on Windows

## When to use

Use this checklist when you suspect a device posing as a keyboard has
been used against a Windows workstation, whether Continuum flagged it
or a person reported something odd: windows opening by themselves, a
command prompt flashing on screen, or an unfamiliar USB stick found in
a port. The goal of triage is to answer three questions quickly: is
this real, is it still happening, and how far could it have reached.

## Steps

1. Check whether Continuum has a matching incident for the same
   workstation and time. A blocked or suspicious verdict with a high
   anomaly score is strong supporting evidence.
2. Identify every USB device currently attached. Compare the list in
   Device Manager (View, Devices by connection) against what the user
   expects to have plugged in. Small boards, unbranded flash drives and
   cables with unusually thick connectors deserve attention, since some
   attack tools are built into cables.
3. Treat vendor and product ids as hints only. Injection tools can
   present any vendor and product id they like, including those of
   well known keyboard brands.
4. Note whether the device enumerated as more than one function, for
   example a keyboard and a mass storage device at the same time. That
   combination is common in attack tools and rare in ordinary
   keyboards.
5. Ask the user what they saw and when. Write down the time, any
   windows that appeared, and whether they were signed in as an
   administrator.
6. Check the Microsoft-Windows-Kernel-PnP/Configuration event log for
   when the device was first configured on this machine. This gives a
   start time for the exposure window.
7. Decide the severity. Escalate immediately if the user had
   administrative rights, if the machine holds sensitive data, or if
   anything suggests commands ran successfully.
8. Hand over to the post-injection command review playbook for the
   detailed investigation.

## Common mistakes

- Trusting the friendly device name. A name such as "HID Keyboard
  Device" is generic and tells you nothing about who made it.
- Rebooting the machine before triage. A reboot clears useful volatile
  state such as running processes and open network connections.
- Assuming the attack failed because the screen looks normal. Many
  payloads close their own windows when finished.
- Focusing only on the keyboard function and forgetting to check for
  storage or network functions exposed by the same device.
