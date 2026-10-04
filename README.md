# Harbinger's Purge

Windows-only CyberPatriot hardening and provisioning toolkit.

## Supported operating systems

- Windows 11
- Windows Server 2022

## Components

### Harbingers-Purge.ps1

The main CyberPatriot hardening executor.

It performs Windows hardening, account reconciliation, password-policy configuration, README-driven checks, service handling, software provisioning, verification, and reporting.

### Harbingers-CyberPatriot-Toolkit.ps1

A GUI-based CyberPatriot toolkit.

The menu provides:

1. Executor
2. Installer / Updater (GUI)
3. Critical Services (GUI)

The Installer / Updater is designed to provide a Ninite-style interface for software required by the CyberPatriot README.

## Usage

Run the toolkit as Administrator.

The toolkit should be placed alongside `Harbingers-Purge.ps1`.

## Important

Do not place CyberPatriot challenge passwords, scoring information, or other sensitive competition material in this public repository.

The software is intended for authorized CyberPatriot training and competition Windows virtual machines.
