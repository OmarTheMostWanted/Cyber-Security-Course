# **Computer Security**

# Lecture 1: Introduction

## What is computer security?
- Computer security deals with protecting data, programs, and systems against intelligent adversaries.
- We become increasingly interconnected, and digitalization is increasing, making the consequences of security failures catastrophic.

## Safety vs Security:
- Safety means being secure against unintended threats.
- Security is the protection against deliberate threats.

## Why is security hard?
- Security is hard to test for.
- Building secure applications requires deep understanding of all technologies involved in the design and implementation of the system.
    - One vulnerability can cripple the system.
    - Not all dependencies are known.
- It is not all technical, users play a role too.
- There is asymmetry between attackers and defenders

## Security principles: CIA triad
- The CIA triad contains the three essential goals in Cyber Security.
- Systems must be **available** to users, users should be able to **trust** (verify) that the data is correct, and data should **not be accessed by unauthorized** persons.


<figure>
  <img src="./assets/CIA-triad.png" style="width: 25%;">
  <figcaption>CIA Triad</figcaption>
</figure>


### Tools for Confidentiality
- Encryption
    - Ensure that data cannot be read when someone gets their hands on it.
- Access control systems
    - Make it hard to get the data when the user is unauthorized.
- Policies and governance
    - Mandate secure data practices
 
### Tools for Integrity
- Data validation
    - Validate data at various stages to ensure that it is still intact.
    - Tools include Checksums, Digital signatures, Error detection and correction codes.
- Change management and version control
    - Control and document changes to data to ensure transparency and accountability.

### Tools for Availability
- Redundancy and failover
    - Design systems with backup mechanisms to mitigate single points of failure.
- Load balancing
    - Distribute traffic across various resources.
- Monitoring and alerting
    - Monitor for early signs of problems to identify system failures before they become a large issue.


## Computer security threat
### Threat definition
- Threats are potential violations of security posed by attackers.
- When evaluating the security of a program or website, it's essential to consider the context:
    Who is the potential attacker, and what are you defending against?

### Context is Crucial
- Computer security is context-dependent and revolves around a specific attacker or threat model.
- There is no universal solution that can defend against all types of threats.

### Attackers have different profiles and motives
- Consider different potential attackers, each with unique motivations and capabilities.
- When evaluating the security of a program or website, it's essential to consider the context: Who is the potential attacker, and what are you defending against?


### No One-Size-Fits-All
Recognize that security measures should be tailored to specific threats and scenarios.
### Continuous Evaluation
Regularly assess and update security measures based on evolving threat landscapes.
### Layered Defense
Implement a multi-layered security approach to address different levels of threats.

## Threat model
- A threat model serves as a strategic framework that identifies potential attacks and adversaries a system aims to safeguard against.
- Threat models help in understanding and preparing for various security risks.

<img src="./assets/threat-model.png" style="width: 50%;">

## Types of threat actors
- Threat actors have varying capabilities. A hacking group backed by a nation has access to much more resources than someone hacking on their own.
- Threat actors have varied motivations, ranging from financial gain to political or ideological reasons.

<img src="./assets/threat-actor.png" style="width: 50%;">

<img src="./assets/threat-profiling.jpg" style="width: 50%;">

## Coordinated Vulnerability Disclosure
- CVD is an ethical practice where security researchers or individuals who discover vulnerabilities in a system responsibly report them to the affected organization.

## Bug bounty program
- A Bug Bounty Program is a crowdsourced initiative where organizations offer rewards to ethical hackers (bug hunters) for responsibly discovering and reporting security vulnerabilities.
- Bug bounty programs incentivize ethical hacking to improve cybersecurity.


## Patch adoption is slow
- Organizations need some time before their systems are patched, and often this takes very long or is not done at all.
    - Organizations do not know that they are running a service or that there is a patch.
    - Organizations do not have clear patching guidelines and admins do it on a “best-effort” basis.
- Because patching is slow, there is a window where organizations are vulnerable even after exploits are readily available.


## Security by design
- Security by design is an approach that integrates cybersecurity measures into the design and development processes of systems and applications from the outset.
- Identifying and addressing security risks early in the development process leads to a more secure product.
- Integrating security from the beginning is more cost-effective than retrofitting security measures later.
- Regulatory requirements make it mandatory to think about security in an early stage.

## Defense in Depth
- Defense in Depth is a cybersecurity strategy that involves deploying multiple layers of security controls to protect against various types of threats.
- This reduces the risk of a single security control failure compromising the entire system.

Usable security
- Usable security is an approach that seeks to integrate effective cybersecurity measures while maintaining a positive and user-friendly experience.
- You can have the best security measures there are, but if it is not usable people will work around them. This can create even more security risks.