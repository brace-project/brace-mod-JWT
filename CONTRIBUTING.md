# Contributing

* Coding standard for the project is [PSR-2](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-2-coding-style-guide.md)
* Any contribution must provide tests for additional/corrected scenarios
* Any un-confirmed issue needs a failing test case before being accepted
* Pull requests must be sent from a new hotfix/feature branch, not from `master`.

## Installation

To install the project and run the tests, you need to clone it first:

```sh
$ git clone git@github.com:brace-project/brace-mod-jwt.git
```

You will then need to install [kickstart](http://nfra.infracamp.org/) to run the test:

```sh
$ kickstart
```

## Testing

The PHPUnit version to be used is the one installed as a dev- dependency via composer:

```sh
$ kick test 
```

Accepted coverage for new contributions is 80%. Any contribution not satisfying this requirement
won't be merged.