# Policy as Code (PAC)

AWS compliance for OPA (written in REGO)

## Introduction

At a corp it is pretty common for teams to adopt several frameworks or tools for checking compliancy. A common usecase for example in Hashicorps Terraform is to check the root of the infra product against Policy as Code, which then tells the engineer (usually before deployment time, so static analysis) if he or she made any booboo's in regards of security and compliance. The same can be done with CloudFormation. Let's name a few regarding the infrastructure as code realm for AWS, like cfn-guard, cfn-nag, sentinel from Hashicorp.

But usually PAC does not stop there. A very big and popular fit for PAC is for example on clusters, reviewing, modifying and even admitting/denying cluster operation commands done over the cluster API. Instead of at the static level, PAC can easily be used at the runtime level as well. Or it is used for IAM of APIs. Plenty of usecases floating around, and plenty of them mature as well.

One very broad and particulary fit DSL for this is REGO, as used by Open Policy Agent (OPA). This tool was intended to be general-purpose and platform-agnostic, and has proven to be a great fit in the ecosystem, looking at the implementation diversity, tooling and popularity.

## PAC for AWS at the static analysis level with OPA in REGO

So why use something specific written for one usecase when you can use a popular general-purpose and platform-agnostic lang?
It might be you do have enough covered out of the box with the specific tool. It's easy to pop in your projects and pipelines, and I love that personally. But when you do need to follow more specific (internal) guidelines / baselines, or your usecases are stricter then the stuff offered out of the box with that tool you could be out of luck, and possibly investing time in writing extends on software that you are not that familiar with. Or leaving the gap open and ignore it, since most sec teams are not on a level that they will actively find out that you were lacking. And AFAIK, no real good static examples of AWS Compliance have been written in REGO. I'd be pretty great if sec and risk/compliance teams and corps would consolidate compliance and regulation enforcement in a more singular format instead of a bunch of different tools, all with the right idea.

That being said, this repo contains several simple, quick examples that cover lots of developer mistakes at the static IAC level.

## Basic usage

Just install OPA, clone this repo, extend on it and run commands similar too:

```sh
opa eval .....
opa eval -i cdk.out/ur.template.json -d ../corp/compliance/corp_aws_landing_zone "data"
opa eval -i cdk.out/ur.template.json -d ../corp/compliance/corp_aws_landing_zone --format pretty "data"
```

Or just run a subset of compliance baselines by going deeper in the structure

```sh
opa eval -i cdk.out/zzz.template.json -d ../../corp/compliance/corp_aws_landing_zone/cis_foundations --format pretty "data"
```
